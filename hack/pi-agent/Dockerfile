FROM node:24-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends bash ca-certificates git ripgrep curl \
  && rm -rf /var/lib/apt/lists/*

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
  && chmod +x kubectl \
  && mv kubectl /usr/local/bin/

RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent

COPY exit.md kubectl.md parallel-subagents.md session-backup.md session-wakeup.md subagent-defaults.md /root/.pi/agent/skills/
COPY exit.ts exec-kubectl.ts load-subagent-defaults.ts prepare-session-hibernation.ts process-session-wakeup.ts session-lib.mjs /root/.pi/agent/extensions/

WORKDIR /workspace
ENTRYPOINT ["pi"]
