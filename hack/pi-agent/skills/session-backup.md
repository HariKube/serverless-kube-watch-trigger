---
name: pi-session-backup
description: Delegate-only session backup: hibernate the parent session, persist the Secret, and create worker PiTriggers after delegation has already been chosen.
---

# Pi Session Backup

Prefer `orchestrate_subagent_execution` when you are still deciding execution mode. Prefer `hibernate_session` only when delegation has already been chosen and you only need the hibernation/write phase.

## Preconditions

- Delegation has already been chosen.
- You already know the worker split.
- Valid `subAgentDefaults` are available.

## Flow

1. Prepare a minimal `workers` list.
2. Call `hibernate_session` with the current prompt/defaults, `nextStep`, and any existing session context.
3. Use the returned `exitReason` or session metadata for the parent handoff.

## Rules

- Only include truly independent work in separate workers.
- Keep `workSoFar` short and decision-relevant.
- Reuse the returned `sessionId`, `secretName`, and cleanup metadata; do not recompute them by hand.
- Use the lower-level `prepare_session_hibernation` tool only when debugging the hibernation planner itself.
