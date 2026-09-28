FROM node:24-bookworm-slim

# Prevent npm update checks and telemetry
ENV NO_UPDATE_NOTIFIER=1
ENV PI_SKIP_VERSION_CHECK=1

RUN apt-get update \
  && apt-get install -y --no-install-recommends bash ca-certificates git ripgrep fd-find curl \
  && ln -s /usr/bin/fdfind /usr/local/bin/fd \
  && rm -rf /var/lib/apt/lists/*

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
  && chmod +x kubectl \
  && mv kubectl /usr/local/bin/

RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent @kubernetes/client-node@2.0.0 billion-context

COPY skills/ /root/.pi/agent/
COPY  extensions/ /root/.pi/agent/

# RUN npm install --no-package-lock --no-audit --no-fund --prefix /root/.pi/agent/extensions typebox

WORKDIR /workspace

# Keep update checks permanently disabled at container runtime
ENV PI_SKIP_VERSION_CHECK=1

ENTRYPOINT ["bili", "pi"]