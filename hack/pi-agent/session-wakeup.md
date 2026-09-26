---
name: pi-session-wakeup
description: Validate wake-up metadata, record a worker result, and decide whether the parent should wait or merge.
---

# Pi Session Wakeup

Run this skill on every prompt that might be a sub-agent report.

## Flow

1. Fetch the session Secret JSON with `exec_kubectl`.
   - If the Secret is not found, stop immediately and call `exit_pi` with a short goodbye reason such as `Goodbye: session secret not found.`
2. If the prompt includes a Job and is not a timeout, also fetch:
   - the Job JSON;
   - the Job Events JSON.
3. Call `process_session_wakeup` with:
   - the full prompt;
   - `secretJson`;
   - optional `jobJson`;
   - optional `eventsJson`;
   - a short `workerSummary`
4. Follow the returned action:
   - `skip`: this is not a wake-up prompt
   - `secret-not-found`: say goodbye and exit; do not recreate anything
   - `not-ready`: the Job is still active; do not decrement anything
   - `already-reported`: do not write again
   - `stale-round`: do not touch the Secret
   - `wait` or `merge`: replace the Secret with `replacementSecretJson` using `exec_kubectl`
5. If the action is `secret-not-found` or `wait`, call `exit_pi` with the returned `exitReason`.
6. If the action is `merge`, continue the parent task using the returned context and stored `result-r*-w*.json` entries.

## Rules

- Never decrement the pending counter outside the extension result.
- Never guess missing wake-up fields.
- Handle `failed`, `timeout`, and `secret-not-found` outcomes explicitly.
