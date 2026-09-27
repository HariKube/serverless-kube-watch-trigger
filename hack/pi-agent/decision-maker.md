---
name: pi-decision-maker
description: Validate whether work should stay local or split into sub-agents before committing to a delegation path.
---

# Pi Decision Maker

Use `decision_maker` before committing to a local-only path or sub-agent handoff.
The tool validates your estimates; it does not inspect candidate task lists, predict step length on its own, or build a concrete parallelization plan for you.

## Flow

1. Summarize the candidate task in one or two sentences.
2. Estimate:
   - `estimatedSteps`
   - `estimatedMinutes`
   - `independentWorkUnits`
3. Pick a tentative `proposedAction` of `stay-local` or `delegate`.
4. Call `decision_maker`.
5. Follow the result:
   - if `approved=true`, continue with the proposed action;
   - if `approved=false`, switch to `recommendedAction`;
   - if `recommendedAction=delegate`, cap workers at `recommendedWorkers` and the session `maxParallel`.

## Rules

- Base estimates on the current path, not best-case optimism.
- Count only truly independent streams as `independentWorkUnits`.
- Treat `warnings` as a signal to tighten the plan before dispatching workers.
- Prefer a short justification with concrete evidence over vague confidence.
- Decide the actual worker split yourself from the code/task context, then use `decision_maker` to validate whether the proposed split should stay local or delegate.
