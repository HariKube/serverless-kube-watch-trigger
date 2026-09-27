---
name: pi-decision-maker
description: Validate whether work should stay local or be delegated, or use the higher-level execution-mode tool when headless is also in play.
---

# Pi Decision Maker

Use `orchestrate_subagent_execution` for the normal decision+delegation path. Use `choose_execution_mode` when you only need the mode decision, and use `decision_maker` only when you specifically want the lower-level stay-local vs delegate judgment.

## Flow

1. Estimate the next step.
2. Prefer `choose_execution_mode` when headless is a possible outcome.
3. If you call `decision_maker`, record a short note stating the question, selected option, and why.

## Rules

- Base estimates on the real next step, not the best case.
- Re-check timeout safety before long work.
- Treat the result as a checkpoint before execution, not a substitute for planning.
