---
name: pi-decision-maker
description: Validate whether work should stay local or be delegated, or use the higher-level execution-mode tool when headless is also in play.
---

# Pi Decision Maker

Use `orchestrate_subagent_execution` for the normal decision+delegation path. Use `choose_execution_mode` when you only need the mode decision, and use `decision_maker` only when you specifically want the lower-level stay-local vs delegate judgment. This skill enforces an autonomous execution policy: do not wait for user clarification or interactive prompts; when the agent is blocked, uncertain, or requires a checkpoint about delegation or execution mode, it must call the `decision_maker` tool, accept the returned decision, and continue executing according to that decision—only stopping when the task is solved or the job reaches `TIMED_OUT`.

## Flow

1. Estimate the next step.
2. Prefer `choose_execution_mode` when headless is a possible outcome.
3. If you call `decision_maker`, record a short note stating the question, selected option, and why. If ever blocked or uncertain, call `decision_maker` immediately (do not pause to ask the user), then proceed with the chosen option and continue autonomous execution until the task is completed or `TIMED_OUT`.

## Rules

- Base estimates on the real next step, not the best case.
- Re-check timeout safety before long work.
- Treat the result as a checkpoint before execution, not a substitute for planning.
- Do not wait for user clarification or prompt for interactive input; when blocked or uncertain you must call the `decision_maker` tool as the required checkpoint.
- After calling `decision_maker`, continue execution according to the selected option (stay-local, delegate, headless, etc.) rather than idling; only stop when the task is solved or the session reaches `TIMED_OUT`.
- Preserve the distinction between `orchestrate_subagent_execution`, `choose_execution_mode`, and `decision_maker`: use the higher-level orchestrator for full delegation flows, `choose_execution_mode` for single-call mode selection, and `decision_maker` as the mandatory checkpoint when blocked or uncertain.
