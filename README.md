# serverless-kube-watch-trigger

A lightweight Kubernetes operator that converts Kubernetes API server watch events into trigger sources for serverless workflows and pi agent jobs.

Key trigger types

- HTTPTrigger — watch Kubernetes resources and send HTTP requests when events match your filters.
- PiTrigger — watch resources and spawn short-lived Kubernetes Jobs that run the `pi` CLI (pi agent) to process each matching event.

What it does

This operator watches selected resource kinds (builtin or CRDs) using efficient watch streams, evaluates optional filters and templates, and dispatches structured trigger events to HTTP endpoints or Pi-based worker Jobs. Use cases include webhooks, AI / model-driven workflows, automation, and integration with external systems without running a separate event bus.

Install

- Releases: install the published YAML bundle from the releases page (https://github.com/HariKube/serverless-kube-watch-trigger/releases) or apply the bundled installer (dist/install.yaml) for a full install.
- Samples & CRDs: sample manifests live under `config/samples/` and the CRDs are in `config/crd` and `config/samples`.

Quick start

1. Install the operator (release bundle or your own build):

   kubectl apply -f https://raw.githubusercontent.com/<org>/serverless-kube-watch-trigger/<tag>/dist/install.yaml

2. Apply a sample trigger:

   kubectl apply -f config/samples/full-httptrigger-example.yaml

3. Inspect status and logs:

   kubectl describe httptrigger <name>   # or pitrigger <name>
   kubectl logs -l control-plane=serverless-kube-watch-trigger

Notes

- The controller requires list/watch RBAC for any kinds you intend to watch; grant additional RBAC if you target extra CRDs or cluster-scoped resources.
- Metrics are available via the controller-runtime `/metrics` endpoint when enabled in the install bundle.

Documentation

See the operator docs in the `docs/` directory for design details, admission webhook examples, multi-replica locking, and PiTrigger session orchestration: ./docs/

Development

Common Makefile targets:

- make test    — run unit tests
- make lint    — run linters
- make build   — compile and build artifacts
- make docker-build / make docker-push — build and publish container images
- make deploy  — deploy controller to cluster (set IMG=...)
- make undeploy — remove controller from cluster
- make install / make uninstall — install or remove CRDs

Contributing

Please open issues or PRs on GitHub. For major changes, open an issue first to discuss design and compatibility.

License

BSD-3-Clause — see LICENSE.
