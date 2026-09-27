---
name: headless
description: Run one bounded, dependent, context-heavy task on a headless worker after execution-mode selection.
---

# Headless Worker

Use `headless` after `choose_execution_mode` selects `headless`, or when an equivalent checkpoint has already ruled out local execution and delegation.

## Good fit

- One dependent stream.
- Self-contained prompt.
- Below the timeout-safety delegation threshold.
- Context-heavy enough that inline execution would bloat the parent.

## Rules

- Keep the prompt explicit and minimal.
- Expect one short final answer plus logs/metadata.
- If the work is long enough to threaten timeout safety, switch to delegated workers instead.
