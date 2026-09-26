---
name: pi-exit
description: End the Pi process only after the current path is fully persisted or intentionally abandoned.
---

# Pi Exit

Use `exit_pi` only as the final tool call on a path.

## Call it when

- the task result is already delivered;
- hibernation state is already saved;
- a failure is already recorded and no more recovery work will happen.

## Rules

- Keep `reason` short and non-sensitive.
- Do not make more tool calls after `exit_pi`.
- Use a larger `delayMs` only when logs are getting cut off.
