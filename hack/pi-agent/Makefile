IMG?=docker.io/mhmxs/pi-agent-empty:latest

MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

all: build push

build:
	docker build -t $(IMG) .

push:
	docker push $(IMG)

test:
	@node --test extensions/*.test.mjs

test-e2e:
	@docker run --rm \
		-e PI_OFFLINE=true \
		-e BILI_CMD= \
		-v $(HOME)/.pi/agent/auth.json:/root/.pi/agent/auth.json \
		-v $(HOME)/.pi/agent/models-store.json:/root/.pi/agent/models-store.json \
		-v $(HOME)/.pi/agent/settings.json:/root/.pi/agent/settings.json \
		$(IMG) -p "what are the available agent tools, extensiond, and skills"

test-e2e-extension:
	@test -n "$(KUBECONFIG)" || (echo "KUBECONFIG must be set and point to a kubeconfig file"; exit 1)
	for f in $(MAKEFILE_DIR)extensions/*.ts; do \
		ext=$$(basename "$$f"); \
		if [ "$$ext" = "exit.ts" ]; then \
			echo "=== skipping exit extension: $$ext (exit.ts skipped) ==="; \
			continue; \
		fi; \
		echo "=== running extension: $$ext ==="; \
		case "$$ext" in \
			exec-kubectl.ts) PROMPT=$$'Inspect the live Kubernetes cluster in namespace "default" (read-only). Read Service "kubernetes", Endpoints "kubernetes", and ConfigMap "kube-root-ca.crt"; report names and contents where safe, do not modify anything. Note recent node-related Events exist and there are no user Pods or Jobs in this namespace snapshot.';; \
			kubernetes-service-discovery.ts) PROMPT=$$'Inspect service discovery for Service "kubernetes" in namespace "default"; verify Endpoints "kubernetes" and related service-like APIs; read-only.';; \
			create-pitrigger.ts) PROMPT=$$'Render (do not apply) a PiTrigger manifest referencing Service "kubernetes" in namespace "default" that would target that Service; explain fields and why it is read-only.';; \
			decision-maker.ts) PROMPT=$$'Given cluster facts (namespace default, Service "kubernetes", ConfigMap "kube-root-ca.crt"), decide which is the better smoke-test target and explain choice; do not mutate cluster.';; \
			execution-mode.ts|subagent-orchestrator.ts|headless.ts) PROMPT=$$'Perform a read-only inspection plan against Service "kubernetes" and ConfigMap "kube-root-ca.crt" in namespace "default", describing expected runtime-only behavior; do not modify cluster.';; \
			job-status.ts) PROMPT=$$'Explain that no Jobs are currently visible in namespace "default"; verify graceful handling for a missing job name and suggest verification steps; do not modify cluster.';; \
			pitrigger-input.ts) PROMPT=$$'Verify/report expected no-op or missing runtime input when PiTrigger env vars are absent, using namespace "default" and Service "kubernetes" as examples; do not modify cluster.';; \
			agent-memory.ts) PROMPT=$$'Report that memory backend prerequisites appear unavailable or summarize/store/query the current default namespace snapshot if possible; be explicit and non-destructive.';; \
			*) PROMPT=$$'Inspect the live Kubernetes cluster (read-only) in namespace "default"; list Services (kubernetes), Endpoints (kubernetes), ConfigMaps (kube-root-ca.crt), recent node Events, and note that no user Pods or Jobs were returned in this snapshot; do not modify anything.';; \
		esac; \
		docker run --rm \
			-e KUBECONFIG=$(KUBECONFIG) \
			-v $(HOME)/.pi/agent/auth.json:/root/.pi/agent/auth.json \
			-v $(HOME)/.pi/agent/models-store.json:/root/.pi/agent/models-store.json \
			-v $(HOME)/.pi/agent/settings.json:/root/.pi/agent/settings.json \
			-v $(MAKEFILE_DIR)extensions:/root/.pi/agent/extensions:ro \
			-v $(KUBECONFIG):$(KUBECONFIG):ro \
			$(IMG) -p "$$PROMPT - Rate execution and call exit_pi with parameters representing the test status."; \\
		read -p "Press [Enter] to continue..."; \
	done
