---
name: pi-session-backup
description: Prepare parent-session hibernation state, worker prompts, and Kubernetes manifests for pending sub-agents.
---

# Pi Session Backup

Use `prepare_session_hibernation` when the parent agent needs to pause and hand work to sub-agents.

## Flow

1. Make sure `subAgentDefaults` is already loaded.
2. Before building workers, estimate an expected worker duration and ask `decision_maker` whether the remaining work should split now or continue locally a bit longer, and to propose or confirm an appropriate worker PiTrigger timeout.
3. Identify which candidate next tasks are truly independent and safe to execute in parallel.
4. Build the `workers` list from only that confirmed parallelizable work. Each worker must have:
   - `index`
   - `task`
   - optional `expectedResult`
   - optional `outputLocation`
   - optional `completed` and `result` for quick work already done locally
5. Before hibernating, ask `decision_maker` to confirm that persisting and pausing the parent session is still the right next move and to validate or refine the chosen worker PiTrigger timeout.
6. Before hibernating, compress the parent session state into a short, high-signal summary:
   - keep decisions, confirmed findings, active constraints, and the exact next step
   - keep only the worker-facing context each pending sub-agent actually needs
   - drop irrelevant chatter, duplicate observations, failed retries, and abandoned dead ends unless they change future decisions
   - store that compact summary in `workSoFar` and use `cleanedPrompt` for a trimmed version of the task when helpful

7. Read the first triggering event payload and capture the original resource owner reference: `apiVersion`, `kind`, `name`, and `metadata.uid`.
8. If the session Secret might already exist, fetch it first with `exec_kubectl` and keep the JSON as `existingSecretJson`.
9. Call `prepare_session_hibernation` with:
   - `subAgentDefaults` (must include the chosen `piTriggerTimeout` duration, e.g., '15m', which will be embedded into created worker PiTrigger manifests)
   - `originalPrompt`
   - `cleanedPrompt`
   - `workSoFar`
   - `nextStep`
   - `workers`
   - `sourceOwnerReference` from the first triggering resource
   - optional `previousContext` for later rounds
   - optional `existingSecretJson` when updating an existing session Secret
10. Apply the returned session Secret first with `exec_kubectl`, and retain the returned cleanup metadata with the session context.
11. If the result indicates that Secret ownership needs a second pass, refetch the session Secret JSON so `existingSecretJson` includes the Secret UID, call `prepare_session_hibernation` again with the same session inputs plus that refreshed `existingSecretJson` (making sure `subAgentDefaults.piTriggerTimeout` still contains the chosen duration), then apply the returned worker PiTrigger manifests. If no second pass is needed, apply the returned worker PiTrigger manifests from the current call.
12. Each pending worker should now have its own session-Secret-owned PiTrigger watching that worker's Kubernetes Job; every PiTrigger uses `maxJobs: 1` and a timeout-based lifecycle, so no worker Lease manifests are involved. Finish with `exit_pi` using the returned `exitReason` after the session Secret and any required second-pass PiTriggers are written successfully.

## What the extension returns

- normalized session context
- cleanup metadata/plan rooted at the session Secret for terminal teardown later
- Secret manifest (create or update-safe when `existingSecretJson` is supplied)
- a high-level signal when the Secret must be refetched with its UID before generating Secret-owned worker PiTriggers
- worker PiTrigger manifests (returned only after the Secret ownership pass has the Secret UID)
- worker prompts
- the pending sub-agent count

## Rules

- Do not modify `subAgentDefaults.agent` by hand after the extension returns it.
- Keep worker indices stable inside a round.
- Use `decision_maker` to challenge optimistic worker splits before creating hibernation manifests and to select a worker PiTrigger timeout; record the chosen duration in `subAgentDefaults.piTriggerTimeout` prior to calling `prepare_session_hibernation` so returned PiTrigger manifests inherit it.
- Only place truly independent tasks in separate workers; keep dependent follow-up work with the parent or in the same worker.
- Compress session context before backup so the resumed parent sees signal, not transcript noise.
- Exclude irrelevant details, duplicate retries, and superseded dead ends unless they are needed to avoid repeating a known bad path.
- Only hibernate after the session Secret and any required second-pass worker PiTriggers are written successfully.
- Keep the returned cleanup metadata with the session context so terminal cleanup deletes only the session Secret and relies on Kubernetes garbage collection to remove Secret-owned PiTriggers plus PiTrigger-owned Jobs and input ConfigMaps.
- If delegation is required but the defaults or session state are invalid, missing, or otherwise unrecoverable, call `exit_pi` with a non-zero `exitCode`.
- Use the returned Secret manifest to update an existing Secret; do not assume the session Secret is create-only.
- Always pass the first triggering resource as `sourceOwnerReference` so Kubernetes can garbage-collect hibernation resources when the original source object is deleted.
