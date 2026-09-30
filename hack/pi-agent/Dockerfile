FROM node:24-bookworm-slim

ARG BILI_CMD?=time

# Prevent npm update checks, audit/fund prompts, progress output and telemetry
ENV NO_UPDATE_NOTIFIER=1
ENV PI_SKIP_VERSION_CHECK=1
ENV PI_OFFLINE=true
ENV BILI_CMD=${BILI_CMD}
ENV NPM_CONFIG_UPDATE_NOTIFIER=false
ENV NPM_CONFIG_AUDIT=false
ENV NPM_CONFIG_FUND=false
ENV NPM_CONFIG_PROGRESS=false

RUN apt-get update \
  && apt-get install -y --no-install-recommends bash ca-certificates git ripgrep fd-find curl \
  && ln -s /usr/bin/fdfind /usr/local/bin/fd \
  && rm -rf /var/lib/apt/lists/*

RUN npm install -g --no-update-notifier --no-fund npm@12.1.0

RUN npm install -g --no-update-notifier --ignore-scripts --no-audit --no-fund @earendil-works/pi-coding-agent billion-context

RUN mkdir -p /root/.pi/agent \
  && npm install --no-update-notifier --ignore-scripts --no-package-lock --no-audit --no-fund --prefix /root/.pi/agent @kubernetes/client-node@2.0.0 typebox

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
  && chmod +x kubectl \
  && mv kubectl /usr/local/bin/

COPY extensions/ /root/.pi/agent/extensions/

WORKDIR /workspace

ENTRYPOINT ["sh", "-c", "exec ${BILI_CMD} pi \"$@\"", "--"]