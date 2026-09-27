---
name: pi-session-wakeup
description: Validate wake-up metadata, record a worker result, and decide whether the parent should wait or merge.
---

# Pi Session Wakeup

Run this skill on every prompt that might be a sub-agent report.

## Flow

1. Inspect the incoming payload/prompt for the literal `TIMED_OUT` before doing any Job lookup.
   - If `TIMED_OUT` is present, treat this wake-up as `trigger deleted`, not as a worker Job timeout.
2. Fetch the session Secret JSON with `exec_kubectl` using the session metadata already present in the wake-up prompt/context.
3. If `TIMED_OUT` was present:
   - do not fetch Job JSON or Event JSON;
   - inspect the session Secret's worker-tracking state and validate the current running-worker count against the Secret label `harikube.info/pending-subagents` and the stored worker/result entries;
   - if this is a terminal abandoned-session path, delete the session Secret and rely on Secret ownership/GC to clean up the temporary PiTriggers plus their Jobs/ConfigMaps;
   - call `exit_pi` immediately with a short `trigger deleted` reason and `exitCode` set to that validated running-worker count.
4. Otherwise, if the prompt includes a Job, also fetch:
   - the Job JSON;
   - the Job Events JSON.
5. Call `process_session_wakeup` with:
   - the full prompt;
   - `secretJson`;
   - optional `jobJson`;
   - optional `eventsJson`;
   - a short `workerSummary`
6. If the returned action is `wait` or `merge`, replace the Secret with `replacementSecretJson` using `exec_kubectl`.
7. If the action is `wait`, call `exit_pi` with the returned `exitReason` and `exitCode: 0` (or omit it).
8. If the action is `merge`, continue the parent task using the returned context and stored `result-r*-w*.json` entries.
9. After a `merge`, ask `decision_maker` what execution mode should come next for the resumed parent work before choosing local continuation, another worker split, or a new hibernation round.
10. When the resumed parent work reaches a terminal outcome without re-hibernating—final successful completion/merge, terminal abort, or unrecoverable terminal error—delete the session Secret as the normal cleanup root and let GC remove the Secret-owned temporary PiTriggers plus their Jobs/ConfigMaps.

## Rules

- Treat any incoming `TIMED_OUT` marker as a deleted-trigger signal.
- On the `TIMED_OUT` / deleted-trigger path, always fetch the session Secret first, validate the running-worker count from the Secret's worker-tracking state/label, and pass that validated number to `exit_pi` as the `exitCode`.
- On the `TIMED_OUT` / deleted-trigger path, never fetch Job/Event data.
- The normal terminal cleanup action is deleting the session Secret, not manually deleting temporary PiTriggers, Jobs, or ConfigMaps one-by-one.
- Deleting the session Secret is what should trigger GC cleanup of Secret-owned PiTriggers and their Jobs/ConfigMaps.
- Use that Secret-deletion cleanup root on terminal abandoned-session paths, after final successful completion following `merge`, and on unrecoverable terminal error/abort paths where the session is finished.
- Keep the non-terminal `wait` path intact: record the result, replace the Secret, and exit without cleanup deletion.
- Never decrement the pending counter outside the extension result.
- Never guess missing wake-up fields.
- Keep the Secret/Job/Event fetch and `process_session_wakeup` handling deterministic; use `decision_maker` only after a successful `merge` transitions control back to the parent task.
