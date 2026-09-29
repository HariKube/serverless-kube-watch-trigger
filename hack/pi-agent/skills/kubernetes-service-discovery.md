---
name: kubernetes-service-discovery
description: Use the native service lookup tool for Kubernetes service discovery. Use the runtime snapshot for stable, read-only follow-up operations.
---

# Kubernetes Service Discovery

## Primary Tool

Use `kubernetes_service_lookup` for name-based discovery.

It searches and merges:

- Controller-discovered service-like APIs
- APIService registry entries
- CRD-backed resources

It returns up to 20 deterministically ranked results.

### Parameters

- `query` — Required lookup string or partial name.
- `limit` — Optional result limit. The maximum is 20.
- `refresh` — Optional. Set to `true` to force fresh discovery.
- `includeDetails` — Optional boolean. When `true`, enriches all result types.
- `details` — Optional list of sources to enrich, such as:
  - `apiservice`
  - `crd`
  - `discovery`

Use the top result when a single match is required.

## Native Details

Details may include:

### APIService resources

- Metadata and status conditions
- Group and version
- Priority and weight
- Referenced Service namespace and name
- Service ports, cluster IP, and related metadata

### CRD-backed resources

- Kind, plural, and singular names
- Resource scope
- Served and storage versions
- OpenAPI schema and validation information
- Stored versions and printer columns
- Canonical resource path

### Discovered API resources

- Group, version, and resource
- Scope and preferred version
- Supported verbs and short names
- Common service-like fields such as ports and selectors
- Resolved Service or endpoint information when available

Request details only when needed because enrichment may require extra discovery calls and RBAC permissions.

## Recommended Workflow

1. Call `kubernetes_service_lookup` with the service name or partial name.
2. Use `refresh: true` when fresh discovery is required.
3. Request details only when additional source information is needed.
4. Use the top-ranked result when one candidate is required.
5. For stable, read-only follow-up operations, use the `kubernetes-service-discovery-runtime` snapshot.
6. Before writing, confirm concrete Kubernetes objects with bounded reads such as `exec_kubectl -o json`.

## Operational Rules

- Treat `kubernetes_service_lookup` as the authoritative tool for string-based discovery.
- Use the runtime snapshot as a supporting per-execution cache, not as the primary lookup.
- Do not assume an API exists when discovery data is missing or stale.
- Perform explicit bounded reads before modifying Kubernetes resources.