---
name: pi-parallel-subagents
description: Decide when to keep work local and when to hand it off to sub-agents.
---

# Pi Parallel Sub-Agents

Use this skill only for work that is clearly larger than one quick local turn.

## Decision rule

- Before executing any step, ask `decision_maker` to predict the length of the next step.
- Stay in the current agent when the predicted next step is short, should finish in about 2 minutes, and is part of a single dependent stream.
- Otherwise, validate the choice with `pi-decision-maker` / `decide_subagent_strategy` before splitting for sub-agents.
- Before dispatching multiple workers, ask `decision_maker` which next tasks can execute in parallel.

## Flow

1. Load defaults with `pi-subagent-defaults`.
2. Estimate the work:
   - `estimatedSteps`
   - `estimatedMinutes`
   - `independentWorkUnits`
3. Before executing the next step, ask `decision_maker` to predict that step's length.
4. Use the predicted step length together with the overall estimates to choose a tentative `proposedAction`.
5. Call `decide_subagent_strategy` with that tentative `proposedAction`.
6. If the tool returns `approved=false`, switch to `recommendedAction`.
7. If the final action is `stay-local`, execute only that next short step in the current agent, then reassess again before the following step.
8. Ask `decision_maker` which next tasks are safe to execute in parallel.
9. If the final action is `delegate` but no validated `subAgentDefaults` are available, stop and report that delegation is unavailable instead of inventing worker config.
10. If the final action is `delegate`, split only the confirmed parallelizable work into 1 to `min(subAgentDefaults.maxParallel, recommendedWorkers)` self-contained workers.
11. Run sub-30-second items locally and mark those workers `completed=true` with a `result`.
12. For the remaining workers, use `pi-session-backup`.
13. On later wake-up prompts, use `pi-session-wakeup`.

## Worker rules

- Each worker gets a unique `index`.
- Each worker should have a unique `outputLocation` when it writes anywhere.
- Independent work goes in separate workers; dependent work stays together.
- Re-check the next-step length with `decision_maker` before every execution step instead of assuming the original plan still holds.
- Do not dispatch workers until the decision has been validated by `decide_subagent_strategy` and `decision_maker` has identified which next tasks can run in parallel.
- Merge failures and timeouts explicitly instead of silently ignoring them.
- Prefer fewer, higher-signal workers over speculative fan-out.
