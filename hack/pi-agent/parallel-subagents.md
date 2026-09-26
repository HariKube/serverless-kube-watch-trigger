---
name: pi-parallel-subagents
description: Decide when to keep work local and when to hand it off to sub-agents.
---

# Pi Parallel Sub-Agents

Use this skill only for work that is clearly larger than one quick local turn.

## Decision rule

- Stay in the current agent when the work is about 5 steps or fewer and should finish in about 2 minutes.
- Otherwise, split it for sub-agents.

## Flow

1. Load defaults with `pi-subagent-defaults`.
2. Split work into 1 to `subAgentDefaults.maxParallel` self-contained workers.
3. Run sub-30-second items locally and mark those workers `completed=true` with a `result`.
4. For the remaining workers, use `pi-session-backup`.
5. On later wake-up prompts, use `pi-session-wakeup`.

## Worker rules

- Each worker gets a unique `index`.
- Each worker should have a unique `outputLocation` when it writes anywhere.
- Independent work goes in separate workers; dependent work stays together.
- Merge failures and timeouts explicitly instead of silently ignoring them.
