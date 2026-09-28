---
name: agent-memory
description: Persist and query ConfigMap-backed agent memories routed by a decision service (save_memory / query_memory).
---

# Agent memory

Use save_memory to persist findings, short summaries, or problem context you want the agent to recall later; use query_memory to fetch relevant memories when solving a problem or preparing a summary.

## Flow / when to use

1. When you discover or generate durable facts, call save_memory with a short problem description, optional findings array, and optional summary.
2. Let the decision service (MEMORY_DECISION_URL) pick the category and bucket for routing; do not attempt to invent categories or buckets locally.
3. When reasoning about a problem, call query_memory with the current problem/summary so the decision service can select buckets; merge the returned memories into your context and prefer the top-sorted results.

## Rules

- Storage is ConfigMap-backed in Kubernetes; memories are written into bucket ConfigMaps and category membership is tracked by a catalog ConfigMap.
- MEMORY_DECISION_URL is required; the decision service determines category + bucket routing for both save and query operations.
- MEMORY_NAMESPACE (defaults to "default") selects the namespace for all memory ConfigMaps; if unset the agent falls back to the Pod namespace or `default`.
- MEMORY_DECISION_TOKEN may be provided for optional bearer authorization when calling the decision service.
- Query results are gathered by reading the selected bucket ConfigMaps, merging and sorting entries before returning; do not rely on strict transactional guarantees—treat saves as eventually consistent and prefer follow-up reads when correctness matters.
- Do not modify or assume the internal ConfigMap layout; use save_memory and query_memory as the supported surface and rely on the decision service for routing.
