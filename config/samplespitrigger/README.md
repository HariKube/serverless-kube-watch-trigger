# PiTrigger sample ideas

This folder contains opinionated `PiTrigger` examples built from the existing samples in `config/samples/`.

## Prerequisites

Apply or adapt the base worker assets from `config/samples/` first:

- `pi-agent-config-secret.yaml`
- `pi-agent-prompts-configmap.yaml`
- `pi-agent-skills-configmap.yaml`
- `pi-agent-worker-rbac.yaml`

## Important notes

- These examples intentionally focus on **trigger design + worker prompt design**.
- Several use cases need broader RBAC than the minimal `pi-agent-worker` example grants.
- Review each prompt before applying it in production, especially anything that could patch or restart workloads.
- For cluster-scoped resources like `Node`, omit `spec.namespaces`.
- The advanced examples below assume a **custom worker image built from `hack/pi-agent/Dockerfile`** so the helper extensions exist at `/root/.pi/agent/extensions/*.ts` inside the worker container.
- Some advanced examples use placeholder CRDs such as `Email` or `Booking`. Replace the sample `apiVersion`, `kind`, selectors, and patch logic with the concrete CRDs used in your platform.

## Included examples

- `node-notready-self-heal.yaml` - watch Node updates and run a self-healing / triage agent.
- `deployment-zero-available-replicas.yaml` - react when a Deployment has zero available replicas.
- `pvc-pending-storage-investigator.yaml` - investigate Pending PVCs.
- `job-failure-responder.yaml` - investigate and respond to failing Jobs.
- `email-sensitive-data-review.yaml` - review an Email object for secrets/regulated data and patch review state safely.
- `transaction-validation-wakeup.yaml` - treat a labeled wake-up signal as an event-driven request to validate the latest transaction and optionally hibernate/delegate follow-up work.
- `federation-booking-acceptance.yaml` - validate and accept a Booking object for federation handoff with auditable patch flow.

## Advanced extension-enabled worker image

To use prompts that call tools from `hack/pi-agent`, build and publish a worker image from:

- `hack/pi-agent/Dockerfile`

That Dockerfile copies the helper extensions into:

- `/root/.pi/agent/extensions/`

The advanced samples explicitly enable extensions such as:

- `exec-kubectl.ts`
- `decision-maker.ts`
- `execution-mode.ts`
- `create-pitrigger.ts`
- `session-backup.ts`
- `session-wakeup.ts`
- `process-session-wakeup.ts`
- `exit.ts`
