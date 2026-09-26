IMG?=docker.io/mhmxs/pi-agent-empty:latest

all: build push

build:
	docker build -t $(IMG) .

push:
	docker push $(IMG)