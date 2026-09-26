---
name: pi-subagent-defaults
description: Load and validate the `sub-agent defaults base64://...` prefix once, then reuse the decoded defaults for the rest of the session.
---

# Pi Sub-Agent Defaults

Use `load_subagent_defaults` at the start of a session when the prompt may include a sub-agent defaults prefix.

## Flow

1. Call `load_subagent_defaults` with the full prompt.
2. If `found=false` on a first-run session, there are no defaults. Do not invent them.
3. If `found=true`, keep both:
   - `subAgentDefaults`: the normalized defaults object;
   - `cleanedPrompt`: the prompt with the prefix removed.
4. Reuse the same `subAgentDefaults` for every later hibernation or wake-up step.

## Rules

- Accept both `sub-agent defaults` and the typo `sub-agent defauls`.
- Never echo the base64 payload back to the user.
- Stop on decode or validation errors.
- Treat the extension output as the source of truth for `namespace`, `leaseDurationSeconds`, and `maxParallel`.
