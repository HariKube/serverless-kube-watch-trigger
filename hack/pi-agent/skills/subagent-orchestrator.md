---
name: pi-subagent-orchestrator
description: Choose stay-local, headless, or delegated execution and, when delegation input is ready, hibernate the parent session plus create worker PiTriggers in one step.
---

# Pi Sub-Agent Orchestrator

Prefer the extension tool `orchestrate_subagent_execution` for the normal execution-selection flow.

## Flow

1. Estimate `estimatedSteps`, `estimatedMinutes`, and `independentWorkUnits`.
2. Call `orchestrate_subagent_execution`.
3. If the tool returns:
   - `selectedMode=stay-local`: continue inline.
   - `selectedMode=headless`: run the bounded task with `headless`.
   - `selectedMode=delegate` and `status=needs-delegation-input`: prepare `delegation.nextStep` and `delegation.workers`, then call it again.
   - `status=hibernated`: the parent session is already persisted and worker PiTriggers are already written.

## Rules

- Keep worker tasks independent and minimal.
- Reuse the returned `sessionId`, `secretName`, and cleanup metadata; do not recompute them by hand.
- Use lower-level helpers such as `choose_execution_mode` or `hibernate_session` only when you explicitly need to split the decision phase from the hibernation/write phase.
