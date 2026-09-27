---
name: pi-parallel-subagents
description: Decide when to keep work local and when to hand it off to sub-agents.
---

# Pi Parallel Sub-Agents

Use this skill only for work that is clearly larger than one quick local turn.

## Decision rule

- Before executing any step, estimate the next step's size yourself from the current code/task context.
- Stay in the current agent when the next step is short, should finish in about 2 minutes, and is part of a single dependent stream.
- Otherwise, validate the choice with `decision_maker` before splitting for sub-agents.
- Identify candidate independent tasks locally, then use `decision_maker` to validate the overall split.

## Flow

1. Load defaults with `pi-subagent-defaults`.
2. Estimate the work:
   - `estimatedSteps`
   - `estimatedMinutes`
   - `independentWorkUnits`
3. Before executing the next step, estimate its size and whether it is still a single dependent stream.
4. Use that estimate together with the overall estimates to choose a tentative `proposedAction`.
5. Call `decision_maker` with that tentative `proposedAction`.
6. If the tool returns `approved=false`, switch to `recommendedAction`.
7. If the final action is `stay-local`, execute only that next short step in the current agent, then reassess again before the following step.
8. Identify which next tasks are truly independent and safe to run in parallel.
9. If the final action is `delegate` but no validated `subAgentDefaults` are available, stop, record the failure, and call `exit_pi` with a non-zero `exitCode` instead of inventing worker config.
10. If the final action is `delegate`, split only the confirmed parallelizable work into 1 to `min(subAgentDefaults.maxParallel, recommendedWorkers)` self-contained workers.
11. Run sub-30-second items locally and mark those workers `completed=true` with a `result`.
12. For the remaining workers, use `pi-session-backup` and follow its session-backup/session-wakeup flow.
13. Do not create per-worker Leases; create or update the session Secret first, then, once the Secret has a UID, create Secret-owned worker PiTriggers, each watching that worker's Job stream with `maxJobs: 1`.
14. On later wake-up prompts, use `pi-session-wakeup`, and when the round is done, delete the session Secret so garbage collection removes the worker resources.

## Worker rules

- Each worker gets a unique `index`.
- Each worker should have a unique `outputLocation` when it writes anywhere.
- Independent work goes in separate workers; dependent work stays together.
- Re-check the next-step size before every execution step instead of assuming the original plan still holds.
- Do not dispatch workers until the decision has been validated by `decision_maker` and you have independently confirmed which tasks can run in parallel.
- Merge failures and timeouts explicitly instead of silently ignoring them.
- Prefer fewer, higher-signal workers over speculative fan-out.
- When delegation cannot proceed because required defaults or session state are invalid or missing, terminate with `exit_pi` and a non-zero `exitCode`.
