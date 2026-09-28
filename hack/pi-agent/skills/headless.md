---
name: headless
description: Run one bounded, dependent, context-heavy task on a headless worker after execution-mode selection.
---

# Headless Worker

Use `headless` after `choose_execution_mode` selects `headless`, or when an equivalent checkpoint has already ruled out local execution and delegation. Headless workers operate autonomously and must not pause to wait for user clarification or input; when blocked or uncertain they must call the `decision_maker` tool and continue executing until the task completes or reaches `TIMED_OUT`.

## Good fit

- One dependent stream.
- Self-contained prompt.
- Below the timeout-safety delegation threshold.
- Context-heavy enough that inline execution would bloat the parent.
- Work that can proceed without waiting for human responses, or that can be resolved via the `decision_maker` when decisions are required.

## Rules

- Do not wait for user clarification or input; the worker must not pause execution to solicit human responses.
- When blocked, uncertain, or facing policy/choice decisions, call the `decision_maker` tool and proceed based on its guidance.
- Continue executing autonomously until the task completes or the runtime reports `TIMED_OUT`.
- Keep the prompt explicit and minimal.
- Expect one short final answer plus logs/metadata.
- If the work is long enough to threaten timeout safety, prefer delegated workers instead.
