# Admission webhook setup for trigger distribution labels

This operator's distributed partition mode expects every `HTTPTrigger` and `PiTrigger` custom resource to carry a `triggers.harikube.info/distribution: item-<1..100>` label.

When `--enable-leader-election=false`, operator replicas divide responsibility by matching that label against the partitions they currently own in the shared `distribution-partition-map` ConfigMap. When leader election stays enabled, the elected leader acts as a single worker and effectively owns all 100 partitions.

> This document is intentionally reference-only. Do **not** embed these examples into `config/webhook`, `config/default`, or runtime deployment manifests unless you explicitly want webhook infrastructure managed separately.

## Label contract

- Label key: `triggers.harikube.info/distribution`
- Allowed values: `item-1` through `item-100`
- Recommended assignment strategy: deterministic hashing from `<namespace>/<name>` into the 1..100 range
- Enforce on both create and update operations so relabeling remains consistent after trigger edits

## Option 1: Native CEL `MutatingAdmissionPolicy` (Kubernetes v1.30+)

The following example computes a stable partition from the trigger namespace and name and writes the label during create and update requests.

```yaml
apiVersion: admissionregistration.k8s.io/v1alpha1
kind: MutatingAdmissionPolicy
metadata:
  name: trigger-distribution-labeler
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["triggers.harikube.info"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["httptriggers", "pitriggers"]
  mutations:
    - patchType: ApplyConfiguration
      applyConfiguration:
        expression: |
          Object{
            metadata: Object.metadata{
              labels: Object.metadata.labels.orValue({}).merge({
                "triggers.harikube.info/distribution":
                  "item-" + string(
                    1 + (
                      int(crc32(string(object.metadata.namespace + "/" + object.metadata.name))) % 100
                    )
                  )
              })
            }
          }
---
apiVersion: admissionregistration.k8s.io/v1alpha1
kind: MutatingAdmissionPolicyBinding
metadata:
  name: trigger-distribution-labeler
spec:
  policyName: trigger-distribution-labeler
  matchResources: {}
```

If your cluster does not expose `crc32()` in CEL, replace the expression with your platform's preferred deterministic hash or fall back to the webhook approach below.

## Option 2: Standard `MutatingWebhookConfiguration`

Use a dedicated admission service that patches the label for both trigger types.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: trigger-distribution-labeler
webhooks:
  - name: httptrigger-distribution.triggers.harikube.info
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail
    reinvocationPolicy: IfNeeded
    clientConfig:
      service:
        namespace: trigger-system
        name: trigger-distribution-webhook
        path: /mutate-httptrigger
    rules:
      - apiGroups: ["triggers.harikube.info"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["httptriggers"]
  - name: pitrigger-distribution.triggers.harikube.info
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail
    reinvocationPolicy: IfNeeded
    clientConfig:
      service:
        namespace: trigger-system
        name: trigger-distribution-webhook
        path: /mutate-pitrigger
    rules:
      - apiGroups: ["triggers.harikube.info"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pitriggers"]
```

Example JSONPatch response body from the webhook implementation:

```json
[
  {
    "op": "add",
    "path": "/metadata/labels",
    "value": {}
  },
  {
    "op": "add",
    "path": "/metadata/labels/triggers.harikube.info~1distribution",
    "value": "item-42"
  }
]
```

## Operational notes

1. Keep the label stable across updates for a given trigger name so ownership does not flap unexpectedly.
2. If you rename a trigger resource, the hash input changes and the label may move to a different partition.
3. In distributed mode, unlabeled triggers are ignored by the partition controller and will not start watcher sessions.
4. The webhook should mutate both `HTTPTrigger` and `PiTrigger` resources before they reach the controller cache.
