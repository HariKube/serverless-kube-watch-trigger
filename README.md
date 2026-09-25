# serverless-kube-watch-trigger
A lightweight Kubernetes operator that turns **Kubernetes API server watch events into trigger sources** for serverless functions, AI workflows, and pi agent jobs. It allows you to declaratively define *when* and *how* webhooks, model calls, or pi-based workers should fire in response to changes in Kubernetes resources — without modifying the API server or deploying heavy eventing frameworks.

## Description
`Serverless-kube-watch-trigger` bridges the gap between **Kubernetes-native resource events** and **serverless workloads**.  
At its core, it watches selected Kubernetes resources (built-in or CRDs) using efficient watch streams, and then dispatches structured trigger events based on user-defined specifications. These triggers can launch serverless functions (e.g. OpenFaaS, Knative), send webhooks, call OpenAI-compatible AI model APIs, spawn pi agent Jobs, or integrate with external systems such as CI/CD pipelines or monitoring tools.

## Installation

Please follow the guide in the [release](https://github.com/HariKube/serverless-kube-watch-trigger/releases) section.

## Documentation

Additional operator documentation lives under [`docs/`](docs/):

- [`docs/admission-webhook-setup.md`](docs/admission-webhook-setup.md) — reference setup for assigning stable `triggers.harikube.info/distribution` labels to `HTTPTrigger` and `PiTrigger` resources, including CEL `MutatingAdmissionPolicy` and `MutatingWebhookConfiguration` examples for distributed partition mode.

### Multi-replica annotation lock

Both `HTTPTrigger` and `PiTrigger` controllers support an optional annotation-based reconcile lease for multi-replica deployments:

* `spec.lockDuration` enables the lease logic for that trigger when set to a non-zero duration.
* The lease is stored on the trigger itself as `triggers.harikube.info/lock-timestamp` with an RFC3339 UTC timestamp.

When enabled, a replica must atomically write the annotation before starting trigger work. If another replica already holds an unexpired lease, the reconcile is **not dropped**: it returns `reconcile.Result{RequeueAfter: remaining}` and retries after the remaining lease window. If two replicas race to acquire the lease, the loser requeues with a short backoff and re-evaluates. After a successful reconcile the controller clears the annotation; if a pod crashes mid-flight, the timestamp expires naturally so another replica can safely resume.

## Getting Started

### 📌 Overview

An `HTTPTrigger` watches a target Kubernetes resource (e.g., `Deployment` or any other Custom Resources), filters events, and sends HTTP requests when matching events happen.

A `PiTrigger` uses the same watch/filter/retry mechanics, but creates a Kubernetes Job that runs `pi` against the matching event payload.

Each trigger consists of:

* **Resource selector** (what to watch)
* **Event filters** (when to trigger)
* **Kind-specific execution target** (where to send or what to run)
* **Payload / runtime configuration** (what to send or how to execute)
* **Delivery / execution policies** (how to deliver or run)

---

### 🧱 Example

```yaml
apiVersion: triggers.harikube.info/v1
kind: HTTPTrigger
metadata:
  name: full-httptrigger-example
  namespace: default
spec:
  resource:
    apiVersion: apps/v1
    kind: Deployment
  namespaces: # Optional
    - default
    - kube-system
  labelSelectors: # Optional
    - app=frontend
    - tier=prod
  fieldSelectors: # Optional
    - metadata.name=my-deployment
  eventTypes: # Optional
    - ADDED
    - MODIFIED
    - DELETED
  eventFilter: 'ne .status.availableReplicas 0' # Optional
  concurrency: 5 # Optional
  sendInitialEvents: false # Optional
  lockDuration: 45s # Optional, enables annotation locking for this trigger using a 45s lease

  # --- Endpoint ---
  url: # Select one option
    static: "https://example.com/hook"
    # template: "https://example.com/hook/{{ .metadata.name }}"
    # service:
    #   name: webhook-svc
    #   namespace: default
    #   portName: https # Optional
    #   scheme: https # Optional 
    #   uri:
    #     template: "/hook/{{ .metadata.name }}"
  method: POST # Optional

  # --- Authentication ---
  auth:
    basicAuth: # Optional
      user: ci-bot
      secretKeyRef:
        name: webhook-pass
        key: password
    tls: # Optional
      caRef:
        name: webhook-ca
        key: ca.crt
      certRef:
        name: webhook-cert
        key: tls.crt
      keyRef:
        name: webhook-cert
        key: tls.key
      insecureSkipVerify: false

  # --- Headers ---
  headers:
    static: # Optional
      X-Static-Token: "fixed-token-value"
      X-Cluster-ID: "cluster-001"
    template: # Optional
      X-Resource-Name: "{{ .metadata.name }}"
      X-Resource-Namespace: "{{ .metadata.namespace }}"
    fromSecretRef: # Optional
      X-Api-Key:
        name: api-secret
        key: api-key
      X-Other-Token:
        name: extra-secrets
        key: token

  # --- Body ---
  body:
    contentType: application/json # Optional
    template: | # Optional
      {{ toJson . }}
    signature: # Optional
      header: X-Signature
      keySecretRef:
        name: sig-key
        key: key
      hmac:
        hashType: SHA512

  # --- Delivery ---
  delivery:
    timeout: 30s # Optional
    retries: 5 # Optional
```

---

### 🖍 Spec Details

#### 🎯 **Resource Selection**

| Field               | Description                                                                            |
| ------------------- | -------------------------------------------------------------------------------------- |
| `resource`          | Target resource kind + API version to watch.                                           |
| `namespaces`        | List of namespaces to watch.                                                           |
| `labelSelectors`    | Optional label selectors to filter resources.                                          |
| `fieldSelectors`    | Optional field selectors to filter resources.                                          |
| `eventTypes`        | Which events to trigger on (`ADDED`, `MODIFIED`, `DELETED`).                           |
| `eventFilter`       | Go template expression evaluated on objects. Return true to trigger. |
| `concurrency`       | Max parallel triggers.                                                                 |
| `sendInitialEvents` | Whether to emit initial events for existing objects.                                   |
| `lockDuration`      | Optional per-trigger annotation lease duration; a non-zero value enables annotation locking for that trigger. |

---

#### 🌐 **Endpoint**

One of:

* `url.static` - fixed URL
* `url.template` - URL template with Go template syntax
* `url.service` - service name + optional URI strategy (static/template)

`method` defines the HTTP verb (default: `POST`).

---

#### 🔐 **Authentication**

Under `auth`, you may configure one or more of:

* `basicAuth`:
  Uses username and password from a secret key reference.

* `tls`:
  mTLS configuration with CA, client cert, and key references.

---

#### 📨 **Headers**

Headers can be defined in three ways:

* `static`: fixed key/value pairs
* `template`: dynamic values using Go templates
* `fromSecretRef`: load header values from Kubernetes secrets

---

#### 🧰 **Body**

Controls the request payload.

| Field         | Description                                                                             |
| ------------- | --------------------------------------------------------------------------------------- |
| `contentType` | Content type of the body (default: `application/json`).                                 |
| `template`    | Go template to generate the request body. `{{ toJson . }}` dumps the full event object. |
| `signature`   | Optional HMAC or static signature added to a header.                                    |

---

#### 🚚 **Delivery**

| Field     | Description                             |
| --------- | --------------------------------------- |
| `timeout` | Maximum request duration (default: `10s`). |
| `retries` | Number of retry attempts on failure.    |

**Retry backoff.** Failed attempts are retried with an exponentially growing
delay between attempts, starting at `1s` and doubling up to a `30s` cap. Every
attempt also honors the per-request `timeout`.

**Sustained-failure gate.** After `3` consecutive failed deliveries the operator
activates a *delivery gate* that spaces out further deliveries to a failing
endpoint, growing from `1s` up to `30s` per delivery. The gate is keyed per
trigger and persists across watcher session restarts, so an endpoint that keeps
failing is not hammered again by a recovering watcher replaying events. Any
successful delivery resets the gate.

**Observability.** Per-trigger delivery metrics are exported on the standard
controller-runtime `/metrics` endpoint under the `serverless_kube_watch_trigger_delivery_*`
family:

| Metric                                        | Labels                                  | Meaning                                  |
| --------------------------------------------- | --------------------------------------- | ---------------------------------------- |
| `delivery_calls_total`                        | `kind`, `trigger`, `method`, `result`, `status_code` | Outgoing endpoint calls by outcome. |
| `delivery_calls_failed_total`                 | `kind`, `trigger`, `method`, `reason`   | Failed calls (`request` vs `status`).    |
| `delivery_call_duration_seconds`              | `kind`, `trigger`, `method`, `result`   | Call latency.                            |
| `delivery_retries_total`                      | `kind`, `trigger`, `method`, `result`   | Retry attempts.                          |
| `delivery_backoffs_total`                     | `kind`, `trigger`                       | Deliveries delayed by the failure gate.  |

`kind` is `httptrigger` or `aitrigger` for outgoing endpoint metrics; `pitrigger`
is also used when PiTrigger executions are delayed by the shared failure gate.
In all cases, `trigger` is the `namespace/name` of the trigger instance.

---

### ⚡ Usage Tips

* Use `{{ toJson . }}` to include the **entire event** as JSON in the body.
* Combine `eventFilter` with label/field selectors for fine-grained control.
* TLS and BasicAuth can be used together if the target requires both mutual TLS and credentials.
* Upon any error, the operator first updates the trigger's status field. It then tries to restart the watcher, resuming from the status.lastResourceVersion.

---

### 🚀 Apply the Trigger

```bash
kubectl apply -f full-httptrigger-example.yaml
```

Then modify or create a matching `Deployment` — the webhook endpoint will receive JSON payloads for every matching event.

---

## 🧠 PiTrigger

`PiTrigger` reuses the same Kubernetes watch semantics as `HTTPTrigger`, but instead of calling an endpoint directly it spawns a Kubernetes Job that runs `pi` directly for each matching event.

### Example

```yaml
apiVersion: triggers.harikube.info/v1
kind: PiTrigger
metadata:
  name: deployment-investigator
  namespace: default
spec:
  resource:
    apiVersion: apps/v1
    kind: Deployment
  namespaces:
    - default
  eventTypes:
    - ADDED
    - MODIFIED
  eventFilter: 'ne .status.availableReplicas 0'
  lockDuration: 45s

  agent:
    image: docker.io/mhmxs/pi-agent-empty:latest
    configSecretRef:
      name: pi-agent-config
    promptsConfigMapRef:
      name: pi-agent-prompts
    skillsConfigMapRef:
      name: pi-agent-skills
    provider: openai
    model: gpt-4o-mini
    workingDir: /workspace
    noExtensions: true
    extensions:
      - npm:pi-graft
    timeout: 10m
    serviceAccountName: pi-trigger-runner
    imagePullPolicy: IfNotPresent
    env:
      - name: PI_ENVIRONMENT
        value: production
    envFrom:
      - secretRef:
          name: pi-agent-credentials
    resources:
      requests:
        cpu: 100m
        memory: 256Mi
      limits:
        cpu: 500m
        memory: 512Mi
    backoffLimit: 3
    activeDeadlineSeconds: 1800
    ttlSecondsAfterFinished: 600
```

### Supporting Secret and ConfigMaps

`PiTrigger` expects one Secret and two ConfigMaps for the pi runtime mounted into each worker Job.

#### Example agent config Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pi-agent-config
  namespace: default
type: Opaque
stringData:
  settings.json: |
    {
      "provider": "freetoken",
      "model": "gtp-oss-20b"
    }
  models.json: |
    {
      "providers": {
        "freetoken": {
          "baseUrl": "http://172.17.0.1:1919/v1",
          "api": "openai-completions",
          "apiKey": "lm-studio",
          "models": [
            {
              "id": "gtp-oss-20b",
              "input": ["text"]
            }
          ]
        }
      }
    }
  models-store.json: |
    {}
  auth.json: |
    {}
```

#### Example prompts ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pi-agent-prompts
  namespace: default
data:
  review.md: |
    Review the triggering Kubernetes event and summarize the most important changes.
```

#### Example skills ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pi-agent-skills
  namespace: default
data:
  SKILL.md: |
    # Example skill
    Use this directory for custom worker skills loaded by PiTrigger jobs.
```

Sample manifests are also available under `config/samples/`.

### Ephemeral AI Triggers & Sleep/Wake Agent Orchestration

HariKube introduces a zero-overhead, event-driven pattern for multi-agent workflows: **Ephemeral Triggers backed by Native Kubernetes Leases**.

Instead of keeping heavy agent processes, long-lived WebSocket connections, or external polling loops continuously running in memory, agents can dynamically create short-lived, self-expiring event watchers `PITrigger`, persist their execution state to the control plane or event stream, and yield compute resources entirely until woken up.

#### How It Works

1. **Transient Registration:** When a parent agent spawns long-running subagent tasks, it creates an `AITrigger` attached to a `coordination.k8s.io/v1` `Lease` resource using standard Kubernetes `OwnerReferences`.
2. **Stateless Offloading:** Before going idle, the agent persists its exact execution context, variables, and step checkpoint directly to the Kubernetes API Server (as a Status field, Annotation, or ConfigMap) or flushes it to the HariKube Kafka event stream.
3. **Resource-Yielding Sleep:** The parent process yields memory and execution threads. The cluster consumes **zero idle compute resources** while waiting for subagents to report back.
4. **Partitioned Storage-Side Wake-Up:** When a subagent completes its work (e.g., updating a CRD or posting a result), HariKube's storage-side filtered watch engine identifies the event and routes it directly to a leaderless worker (scaling up to 100+ parallel Go goroutines).
5. **State Reload & Resume:** The awakened worker loads the persisted state snapshot from Kafka or the API Server, restores context, and resumes execution seamlessly.
6. **Self-Cleaning Lifecycle:** Once the event is delivered—or if a lease expires without renewal—Kubernetes Garbage Collection automatically sweeps the temporary trigger. No leftover state, no manual `DELETE` cleanup calls.

#### What Is It Good For?

* **Zero-Idle Multi-Agent Workflows:** Run complex multi-step AI pipelines without paying for idle server time. Agents only consume resources when actively processing data.
* **Resilient Distributed Checkpointing:** Since execution state is committed to Kafka or the Kubernetes API Server before sleeping, agents can survive node restarts, rescheduling, or pod evictions without losing progress.
* **Leaderless Parallel Concurrency:** Bypasses traditional single-leader `etcd` bottlenecks. Hundreds of transient triggers can reconcile simultaneously across independent storage partition workers.
* **No External Queue Dependencies:** Eliminates the need for Redis, Celery, or external pub/sub brokers. Distributed locking, event routing, and TTL state are handled natively by Kubernetes control plane primitives with atomic Optimistic Concurrency Control (OCC).
* **Native RBAC & Network Security:** Ephemeral agent triggers inherit standard Kubernetes security semantics out of the box—no custom permission systems required.

### Building a custom PiTrigger worker image

Because `PiTrigger` now runs `pi` directly in the Job container, the worker image can use a normal `pi` image `ENTRYPOINT`.

A good baseline looks like this:

```dockerfile
FROM node:24-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends bash ca-certificates git ripgrep \
  && rm -rf /var/lib/apt/lists/*
RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent

WORKDIR /workspace
ENTRYPOINT ["pi"]
```

You only need:

* the `pi` CLI
* any OS tools your prompts or skills need (`bash`, `git`, `ripgrep`, etc.)
* an existing working directory such as `/workspace`

Optional extensions can still be baked into the image, for example:

```dockerfile
FROM node:24-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    git \
    ripgrep \
  && rm -rf /var/lib/apt/lists/*

RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent

# Optional: bake extensions directly into the image
# RUN npm install -g --ignore-scripts pi-graft

WORKDIR /workspace
ENTRYPOINT ["pi"]
```

Build and push it like any other container image:

```bash
docker build -t ghcr.io/<your-org>/pi-trigger-worker:latest -f Dockerfile.pi-worker .
docker push ghcr.io/<your-org>/pi-trigger-worker:latest
```

Then reference it from `spec.agent.image`.

### Including extensions

You can load pi extensions in two ways:

#### Bake extensions into the image

Install them with `npm install -g` during image build:

```dockerfile
RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent
RUN npm install -g --ignore-scripts pi-graft
```

Then explicitly enable them in the trigger:

```yaml
agent:
  noExtensions: true
  extensions:
    - npm:pi-graft
```

#### Mount prompts and skills dynamically

Use `promptsConfigMapRef` and `skillsConfigMapRef` to provide runtime content without rebuilding the image. The controller mounts them into the worker home under:

* `~/.pi/agent/prompts`
* `~/.pi/agent/skills`

This is the easiest way to ship team-specific prompts, reusable skills, or per-environment customizations.

### Image and runtime notes

* `configSecretRef` is mounted into the worker home as the pi agent config directory.
* `promptsConfigMapRef` and `skillsConfigMapRef` are mounted on top of that same worker home.
* `provider`, `model`, `noExtensions`, and `extensions` are passed to `pi` as container args.
* `workingDir` is applied as the container working directory.
* `timeout` is applied to the Job runtime by defaulting `activeDeadlineSeconds` when that field is not set explicitly.
* `workingDir` should exist in the image, for example `/workspace`.
* If your prompts run shell commands, install the required binaries in the image.

### PiTrigger fields

`PiTrigger` supports the same:

* resource selection (`resource`, `namespaces`, `labelSelectors`, `fieldSelectors`, `eventTypes`, `eventFilter`)
* watcher controls (`concurrency`, `sendInitialEvents`, `lockDuration`)
* status handling and automatic watcher restart behavior

In addition, `spec.agent` defines the spawned worker Job:

| Field | Description |
| --- | --- |
| `image` | Required container image used for the spawned pi worker Job. |
| `configSecretRef` | Required Secret mounted into `~/.pi/agent`; it must contain `settings.json`, `models.json`, `models-store.json`, and `auth.json`. |
| `promptsConfigMapRef` | Required ConfigMap mounted into `~/.pi/agent/prompts`. |
| `skillsConfigMapRef` | Required ConfigMap mounted into `~/.pi/agent/skills`. |
| `provider` | Optional pi provider passed to the spawned `pi` process. |
| `model` | Optional pi model passed to the spawned `pi` process. |
| `workingDir` | Optional working directory used by the worker container. |
| `noExtensions` | Optional flag controlling ambient pi extension loading; defaults to `true`. |
| `extensions` | Optional explicit pi extensions to load for the worker. |
| `timeout` | Optional runtime limit that defaults `activeDeadlineSeconds` when not set explicitly. |
| `serviceAccountName` | Optional ServiceAccount override for spawned Jobs. |
| `imagePullPolicy` | Optional pull policy for the worker image. |
| `env` | Optional extra environment variables added to the worker container. |
| `envFrom` | Optional bulk environment imports from Secrets or ConfigMaps. |
| `resources` | Optional CPU and memory requests and limits for the worker container. |
| `backoffLimit` | Optional Kubernetes Job retry limit for a failed worker. |
| `activeDeadlineSeconds` | Optional maximum total runtime for a worker Job. |
| `ttlSecondsAfterFinished` | Optional automatic cleanup TTL for completed Jobs. |

### Notes

* Each matching event produces a ConfigMap with `event.json` and `metadata.json`, then the operator creates a Job to run `pi`.
* `event.json` contains the watched object payload and `metadata.json` contains trigger and resource-version metadata for the run.
* Use `promptsConfigMapRef` and `skillsConfigMapRef` to ship custom prompts and skills with the worker image.
* The Job keeps the image `ENTRYPOINT` and passes `pi` runtime options through container args.

---

### 🧪 Debugging

* Use `kubectl describe httptrigger <name>`, `kubectl describe aitrigger <name>`, or `kubectl describe pitrigger <name>` to inspect status and events.
* Check controller logs for the trigger type you are debugging, and inspect spawned PiTrigger Jobs with `kubectl get jobs` / `kubectl logs job/<name>` when using `PiTrigger`.
* Use `toPrettyJson` in templates to make payloads human-readable during testing.

## Development

### Prerequisites
- go version v1.24.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/serverless-kube-watch-trigger:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/serverless-kube-watch-trigger:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following the options to release and provide this solution to the users.

### By providing a bundle with all YAML files

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/serverless-kube-watch-trigger:tag
```

**NOTE:** The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without its
dependencies.

2. Using the installer

Users can just run 'kubectl apply -f <URL for YAML BUNDLE>' to install
the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/serverless-kube-watch-trigger/<tag or branch>/dist/install.yaml
```

### By providing a Helm Chart

1. Build the chart using the optional helm plugin

```sh
kubebuilder edit --plugins=helm/v1-alpha
```

2. See that a chart was generated under 'dist/chart', and users
can obtain this solution from there.

**NOTE:** If you change the project, you need to update the Helm Chart
using the same command above to sync the latest changes. Furthermore,
if you create webhooks, you need to use the above command with
the '--force' flag and manually ensure that any custom configuration
previously added to 'dist/chart/values.yaml' or 'dist/chart/manager/manager.yaml'
is manually re-applied afterwards.

## 🤝 Contribution Guide

We welcome and encourage contributions from the community! Whether it's a bug fix, a new feature, or an improvement to the documentation, your help is greatly appreciated.

Before you get started, please take a moment to review our guidelines:

- Read the Documentation: Start with this README and the additional documents under [`docs/`](docs/) to familiarize yourself with the operator's architecture and existing features.
- Open an Issue: For any significant changes or new features, please open an issue first to discuss the idea. This helps prevent duplicated work and ensures alignment with the project's goals.
- Fork the Repository: Fork the repository to your own GitHub account.
- Create a Branch: Create a new branch for your feature or bug fix: git checkout -b feature-my-awesome-feature.
- Commit Your Changes: Make your changes and commit them with a clear and descriptive message.
- Submit a Pull Request: Push your branch to your forked repository and open a pull request against the main branch of this repository. Please provide a clear description of your changes in the PR.

We are committed to providing a friendly, safe, and welcoming environment for all, regardless of background or experience. We are following Kubernetes Please see them [Code of Conduct](https://kubernetes.io/community/code-of-conduct/) for more details.

## 🙏 Share Feedback and Report Issues

Your feedback is invaluable in helping us improve this operator. If you encounter any issues, have a suggestion for a new feature, or simply want to share your experience, we want to hear from you!

- Report Bugs: If you find a bug, please open a [GitHub Issue](https://github.com/HariKube/serverless-kube-watch-trigger/issues). Include as much detail as possible, such as steps to reproduce the bug, expected behavior, and your environment (e.g., Kubernetes version, Go version).
- Request a Feature: If you have an idea for a new feature, open a [GitHub Issue](https://github.com/HariKube/serverless-kube-watch-trigger/issues) and use the `enhancement` label. Describe the use case and how the new feature would benefit the community.
- Ask a Question: For general questions or discussions, please use the [GitHub Discussions](https://github.com/HariKube/serverless-kube-watch-trigger/discussions).

## 📝 License

This project is licensed under the BSD 3-Clause "New" or "Revised" License. See the LICENSE file for details.

## ✨ Special Thanks

We'd like to extend our gratitude to the Kubernetes community and the developers of related projects like controller-runtime and kubebuilder for their foundational work that inspired and enabled the creation of this framework.

