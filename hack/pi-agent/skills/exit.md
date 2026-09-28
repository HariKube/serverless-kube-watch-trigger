---
name: pi-exit
description: Terminate the Pi process only after the agent has reached a true completion or after required state has been durably persisted and handed off; do not use exit to pause or wait for user input.
---

# Pi Exit

Use `exit_pi` only as the final tool call on a path when the agent is actually done or has safely persisted a handoff for later resumption.

## Call it when

- the task result has been delivered and acknowledged;
- hibernation or resume state has been durably saved to persistent storage;
- work has been intentionally and durably handed off to an external actor or system; or
- a terminal, non-recoverable failure has been recorded and no further recovery attempts will be undertaken.

## Rules

- Keep `reason` short and non-sensitive.
- Do not make more tool calls after `exit_pi`.
- Use a larger `delayMs` only when logs are getting cut off and need time to flush.
- Do not use `exit_pi` as a mechanism to pause or wait for user input; the agent should continue operating autonomously (making decisions, taking actions, or persisting state) until an explicit completion or durable handoff is reached.
- Use `exitCode: 0` (or omit it) only for true successful completion or when the agent has durably persisted state for a legitimate handoff/hibernation that allows later resumption.
- Use a non-zero `exitCode` for unrecoverable errors such as invalid input, missing required session state, or failed validation where the current path cannot recover.
