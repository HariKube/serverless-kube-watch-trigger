---
name: pi-session-backup
description: Prepare parent-session hibernation state, worker prompts, and Kubernetes manifests for pending sub-agents.
---

# Pi Session Backup

Use `prepare_session_hibernation` when the parent agent needs to pause and hand work to sub-agents.

## Flow

1. Make sure `subAgentDefaults` is already loaded.
2. Before building workers, ask `decision_maker` whether the remaining work should split now or continue locally a bit longer.
3. Ask `decision_maker` which candidate next tasks are truly independent and safe to execute in parallel.
4. Build the `workers` list from only that confirmed parallelizable work. Each worker must have:
   - `index`
   - `task`
   - optional `expectedResult`
   - optional `outputLocation`
   - optional `completed` and `result` for quick work already done locally
5. Before hibernating, ask `decision_maker` to confirm that persisting and pausing the parent session is still the right next move.
6. Before hibernating, compress the parent session state into a short, high-signal summary:
   - keep decisions, confirmed findings, active constraints, and the exact next step
   - keep only the worker-facing context each pending sub-agent actually needs
   - drop irrelevant chatter, duplicate observations, failed retries, and abandoned dead ends unless they change future decisions
   - store that compact summary in `workSoFar` and use `cleanedPrompt` for a trimmed version of the task when helpful

7. Read the first triggering event payload and capture the original resource owner reference: `apiVersion`, `kind`, `name`, and `metadata.uid`.
8. If the session Secret might already exist, fetch it first with `exec_kubectl` and keep the JSON as `existingSecretJson`.
9. Call `prepare_session_hibernation` with:
   - `subAgentDefaults`
   - `originalPrompt`
   - `cleanedPrompt`
   - `workSoFar`
   - `nextStep`
   - `workers`
   - `sourceOwnerReference` from the first triggering resource
   - optional `previousContext` for later rounds
   - optional `existingSecretJson` when updating an existing session Secret
10. Apply the returned Secret, Lease, and PiTrigger manifests with `exec_kubectl`.
11. Finish with `exit_pi` using the returned `exitReason`.

## What the extension returns

- normalized session context
- Secret manifest (create or update-safe when `existingSecretJson` is supplied)
- Lease manifests
- PiTrigger manifests
- worker prompts
- the pending sub-agent count

## Rules

- Do not modify `subAgentDefaults.agent` by hand after the extension returns it.
- Keep worker indices stable inside a round.
- Use `decision_maker` to challenge optimistic worker splits before creating hibernation manifests.
- Only place truly independent tasks in separate workers; keep dependent follow-up work with the parent or in the same worker.
- Compress session context before backup so the resumed parent sees signal, not transcript noise.
- Exclude irrelevant details, duplicate retries, and superseded dead ends unless they are needed to avoid repeating a known bad path.
- Only hibernate after the Secret, Leases, and PiTriggers are written successfully.
- Use the returned Secret manifest to update an existing Secret; do not assume the session Secret is create-only.
- Always pass the first triggering resource as `sourceOwnerReference` so Kubernetes can garbage-collect hibernation resources when the original source object is deleted.
