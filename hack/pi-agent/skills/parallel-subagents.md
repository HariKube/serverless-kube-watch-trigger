---
name: pi-parallel-subagents
description: Choose stay-local, headless, or delegated execution while minimizing worker context and using shared timeout-safety rules.
---

# Pi Parallel Sub-Agents

Prefer the extension tool `orchestrate_subagent_execution`. Use `choose_execution_mode` only when you want the decision without immediate delegation setup.

## Flow

1. Estimate `estimatedSteps`, `estimatedMinutes`, and `independentWorkUnits`.
2. Call `orchestrate_subagent_execution`.
3. Follow `selectedMode`:
   - `stay-local`: do the next bounded step inline.
   - `headless`: use the `headless` tool for one dependent, context-heavy stream.
   - `delegate`: provide `delegation.nextStep` plus `delegation.workers` so the same tool can hibernate the parent session and create worker PiTriggers.

## Rules

- Re-evaluate mode before each major step instead of assuming the first choice still holds.
- Prefer `delegate` when work reaches the timeout-safety window or splits cleanly into independent units.
- Prefer `headless` only for one bounded stream that is still below the delegation threshold.
- Keep worker context minimal and self-contained.
