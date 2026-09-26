---
name: pi-session-backup
description: Prepare parent-session hibernation state, worker prompts, and Kubernetes manifests for pending sub-agents.
---

# Pi Session Backup

Use `prepare_session_hibernation` when the parent agent needs to pause and hand work to sub-agents.

## Flow

1. Make sure `subAgentDefaults` is already loaded.
2. Build the `workers` list. Each worker must have:
   - `index`
   - `task`
   - optional `expectedResult`
   - optional `outputLocation`
   - optional `completed` and `result` for quick work already done locally
3. Before hibernating, compress the parent session state into a short, high-signal summary:
   - keep decisions, confirmed findings, active constraints, and the exact next step
   - keep only the worker-facing context each pending sub-agent actually needs
   - drop irrelevant chatter, duplicate observations, failed retries, and abandoned dead ends unless they change future decisions
   - store that compact summary in `workSoFar` and use `cleanedPrompt` for a trimmed version of the task when helpful

4. Read the first triggering event payload and capture the original resource owner reference: `apiVersion`, `kind`, `name`, and `metadata.uid`.
5. If the session Secret might already exist, fetch it first with `exec_kubectl` and keep the JSON as `existingSecretJson`.
6. Call `prepare_session_hibernation` with:
   - `subAgentDefaults`
   - `originalPrompt`
   - `cleanedPrompt`
   - `workSoFar`
   - `nextStep`
   - `workers`
   - `sourceOwnerReference` from the first triggering resource
   - optional `previousContext` for later rounds
   - optional `existingSecretJson` when updating an existing session Secret
7. Apply the returned Secret, Lease, and PiTrigger manifests with `exec_kubectl`.
8. Finish with `exit_pi` using the returned `exitReason`.

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
- Compress session context before backup so the resumed parent sees signal, not transcript noise.
- Exclude irrelevant details, duplicate retries, and superseded dead ends unless they are needed to avoid repeating a known bad path.
- Only hibernate after the Secret, Leases, and PiTriggers are written successfully.
- Use the returned Secret manifest to update an existing Secret; do not assume the session Secret is create-only.
- Always pass the first triggering resource as `sourceOwnerReference` so Kubernetes can garbage-collect hibernation resources when the original source object is deleted.
