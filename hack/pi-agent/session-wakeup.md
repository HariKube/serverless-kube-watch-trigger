---
name: pi-session-wakeup
description: Fetch wake-up state, record a worker result, and decide whether the parent should wait or merge.
---

# Pi Session Wakeup

Prefer the extension tool `handle_session_wakeup`.

## Flow

1. Call `handle_session_wakeup` on prompts that may be worker reports.
2. Follow the returned action:
   - `skip`: not a wake-up prompt.
   - `not-ready`: worker Job is still running.
   - `wait`: result recorded, more workers remain.
   - `merge`: all workers reported; resume parent work.
   - `already-reported` or `secret-not-found`: treat as idempotent/terminal bookkeeping paths.

## Rules

- Let the extension own Secret fetches, Job/Event fetches, and conflict retries.
- Never decrement pending counters by hand.
- After a successful `merge`, re-evaluate execution mode before continuing.
- Use the lower-level `process_session_wakeup` tool only when debugging the wake-up state machine itself.
