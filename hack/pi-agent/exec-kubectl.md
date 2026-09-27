---
name: kubectl
description: Run one bounded kubectl command in the current cluster with the Pod ServiceAccount.
---

# Kubernetes with `exec_kubectl`

Use `exec_kubectl` for one-off reads or writes. Prefer higher-level session tools like `hibernate_session` and `handle_session_wakeup` for the standard hibernation/wake-up flows.

## Rules

- Pass exactly one kubectl command.
- Do not include the `kubectl` prefix.
- Prefer structured output like `-o json`.
- Prefer `input` over shell here-docs.
- Use follow-up reads when correctness matters.
