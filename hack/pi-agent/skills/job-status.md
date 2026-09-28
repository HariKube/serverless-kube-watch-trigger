---
name: job_status
description: Bounded diagnostics read for a worker Job, its related Events, and Pods to inform timeout/failure cleanup.
---

# Job Status Diagnostics (`job_status`)

Use `job_status` when handling TIMED_OUT or similar timeout-cleanup prompts for a worker Job; it performs bounded, read-only diagnostics and returns a compact verdict (timed_out / failed / ok / not_found) along with summarized Job status, related Events, and Pods.

## When to call

- Call this as the first step in a timeout cleanup flow to understand why a Job did not complete (deadline, backoff, OOMKilled, container exit codes, etc.).
- Prefer reads here — do not create Events or delete Secrets in this tool; use its diagnostics to decide whether those writes are appropriate.

## What it returns / diagnostics it provides

- A high-level verdict: `timed_out`, `failed`, `ok`, or `not_found`.
- Derived booleans and reasons: `timedOut`, `timedOutReason`, `failed`, `failureReason`.
- Summarized Job status (succeeded/failed/active counts and conditions).
- A compact list of related Events (reason, type, message, timestamps) and inferred matches for timeout/backoff/failure.
- A compact list of Pods selected by `job-name=<job>` with phases and containerStatuses (terminated/waiting info, exit codes, restart counts).
- Optional raw payloads for Job, Events, and Pods when `includeRawJob`, `includeRawEvents`, or `includeRawPods` are requested.

## Guidance for timeout cleanup flows

- Use `job_status` output to determine if the Job truly timed out (deadline/backoff) versus transient failures; prefer event and pod termination details to attribute root cause.
- If the verdict indicates `timed_out` or a clear failure, the caller may then create a Kubernetes Event recording the automation's decision and/or delete the session Secret — but perform those writes outside this tool and with appropriate idempotency/authorization checks.
- If `not_found`, treat the Job as already absent and avoid further deletion attempts for its Secret unless you can confirm a matching session mapping.
- When in doubt, gather raw payloads (`includeRaw*`) and follow-up reads before mutating cluster state.

## Rules

- This tool must only perform bounded reads; never perform writes (Events, Secrets, Jobs) — those responsibilities belong to the higher-level cleanup orchestrator.
- Keep calls short and deterministic: prefer `-o json` structured output and use follow-up reads when needed for clarity.

