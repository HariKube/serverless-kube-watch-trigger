---
name: create-pitrigger
description: Create or prepare a PiTrigger manifest when you need a standalone trigger outside the higher-level hibernation/session helpers.
---

# Create PiTrigger (`create_pitrigger`)

Use `create_pitrigger` when you need a dedicated PiTrigger and do not want the full `hibernate_session` flow.
Prefer `hibernate_session` or `prepare_session_hibernation` for the built-in sub-agent fan-out/session pattern.

## When to use

- Create a one-off PiTrigger for a watched resource.
- Prepare a PiTrigger manifest for review without applying it yet.
- Reuse runtime `subAgentDefaults` so the trigger inherits the current worker image/config/skills/agent settings.
- Override only `model`, `provider`, or `serviceAccountName` without rebuilding the entire nested `agent` object.

## Flow

1. Provide `name` and `resource`.
2. Provide `agent`, or pass `subAgentDefaults` so the tool can reuse `subAgentDefaults.agent`.
3. If needed, override only `model`, `provider`, or `serviceAccountName`; the rest of the agent settings still inherit from `subAgentDefaults.agent`.
4. Customize `labelSelectors` and `eventTypes` explicitly when the watch should be narrower than the defaults.
5. Set `apply=false` when you want to inspect the manifest before creating it.
6. When correctness matters, follow up with a bounded read such as `exec_kubectl` and `-o json`.

## Rules

- `labelSelectors` is agent-controlled; pass the exact selector list needed for the trigger.
- `eventTypes` is agent-controlled; pass any subset of `ADDED`, `MODIFIED`, and `DELETED`.
- Prefer explicit `labelSelectors`, `fieldSelectors`, and `eventTypes` over broad watches.
- If you are creating delegated worker PiTriggers for a session, prefer the higher-level session helpers.
- When `subAgentDefaults.agent` is available, prefer small overrides such as `model` or `serviceAccountName` instead of rewriting the whole nested `agent` object.
- Do not invent missing agent config; either pass `agent` explicitly or reuse validated `subAgentDefaults.agent`.
