---
name: kubectl
description: Run one bounded kubectl command in the current cluster with the Pod ServiceAccount.
---

# Kubernetes with `exec_kubectl`

Use `exec_kubectl` for cluster reads and writes.

## Parameters

- `command`: everything after `kubectl`
- `namespace` (optional): passed as `-n <namespace>`
- `input` (optional): STDIN for `apply -f -` or `replace -f -`
- `retryOnConflict` (optional): retries replace/apply conflicts

## Rules

- Pass exactly one kubectl command.
- Do not include the `kubectl` prefix.
- Use structured output like `-o json` when another tool will read it.
- Prefer `input` over shell here-docs.
- Verify writes with a follow-up read when correctness matters.
