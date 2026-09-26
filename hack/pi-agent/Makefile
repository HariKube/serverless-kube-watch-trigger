IMG?=docker.io/mhmxs/pi-agent-empty:latest

all: build push

build:
	docker build -t $(IMG) .

push:
	docker push $(IMG)

test:
	@docker run -it --rm \
		-e PI_OFFLINE=true \
		-v $(HOME)/.pi/agent/auth.json:/root/.pi/agent/auth.json \
		-v $(HOME)/.pi/agent/models-store.json:/root/.pi/agent/models-store.json \
		-v $(HOME)/.pi/agent/settings.json:/root/.pi/agent/settings.json \
		docker.io/mhmxs/pi-agent-empty:latest "hi"