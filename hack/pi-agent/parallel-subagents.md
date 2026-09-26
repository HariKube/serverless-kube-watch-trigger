---
name: pi-parallel-subagents
description: Decide when to keep work local and when to hand it off to sub-agents.
---

# Pi Parallel Sub-Agents

Use this skill only for work that is clearly larger than one quick local turn.

## Decision rule

- Stay in the current agent when the work is about 5 steps or fewer, should finish in about 2 minutes, and is a single dependent stream.
- Otherwise, validate the choice with `pi-decision-maker` before splitting for sub-agents.

## Flow

1. Load defaults with `pi-subagent-defaults`.
2. Estimate the work:
   - `estimatedSteps`
   - `estimatedMinutes`
   - `independentWorkUnits`
3. Call `decide_subagent_strategy` with a tentative `proposedAction`.
4. If the tool returns `approved=false`, switch to `recommendedAction`.
5. If the final action is `stay-local`, finish the work in the current agent.
6. If the final action is `delegate` but no validated `subAgentDefaults` are available, stop and report that delegation is unavailable instead of inventing worker config.
7. If the final action is `delegate`, split work into 1 to `min(subAgentDefaults.maxParallel, recommendedWorkers)` self-contained workers.
8. Run sub-30-second items locally and mark those workers `completed=true` with a `result`.
9. For the remaining workers, use `pi-session-backup`.
10. On later wake-up prompts, use `pi-session-wakeup`.

## Worker rules

- Each worker gets a unique `index`.
- Each worker should have a unique `outputLocation` when it writes anywhere.
- Independent work goes in separate workers; dependent work stays together.
- Do not dispatch workers until the decision has been validated by `decide_subagent_strategy`.
- Merge failures and timeouts explicitly instead of silently ignoring them.
- Prefer fewer, higher-signal workers over speculative fan-out.
