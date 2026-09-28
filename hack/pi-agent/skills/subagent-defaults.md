---
name: pi-subagent-defaults
description: Resolve sub-agent defaults for the current session, preferring injected runtime defaults and falling back to the legacy prompt prefix only when necessary.
---

# Pi Sub-Agent Defaults

Prefer `orchestrate_subagent_execution` or `resolve_subagent_defaults`. The orchestrator already resolves defaults before choosing a mode or hibernating a session.

## Flow

1. Call `resolve_subagent_defaults` once near the start of any delegation, hibernation, or wake-up path.
2. Reuse the returned `subAgentDefaults` and `cleanedPrompt` for the rest of the session.
3. If `found=false`, do not invent defaults.

## Rules

- Prefer runtime defaults over prompt parsing.
- Never echo the legacy base64 payload back to the user.
- Treat the returned object as the source of truth for namespace, maxParallel, timeout, and embedded `agent` settings.
- Only fall back to the lower-level `load_subagent_defaults` tool when debugging the resolver itself.
