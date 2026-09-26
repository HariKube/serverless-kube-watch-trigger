---
name: pi-decision-maker
description: Validate whether work should stay local or split into sub-agents before committing to a delegation path.
---

# Pi Decision Maker

Use `decide_subagent_strategy` before committing to a local-only path or sub-agent handoff.

## Flow

1. Summarize the candidate task in one or two sentences.
2. Estimate:
   - `estimatedSteps`
   - `estimatedMinutes`
   - `independentWorkUnits`
3. Pick a tentative `proposedAction` of `stay-local` or `delegate`.
4. Call `decide_subagent_strategy`.
5. Follow the result:
   - if `approved=true`, continue with the proposed action;
   - if `approved=false`, switch to `recommendedAction`;
   - if `recommendedAction=delegate`, cap workers at `recommendedWorkers` and the session `maxParallel`.

## Rules

- Base estimates on the current path, not best-case optimism.
- Count only truly independent streams as `independentWorkUnits`.
- Treat `warnings` as a signal to tighten the plan before dispatching workers.
- Prefer a short justification with concrete evidence over vague confidence.
