# 1. Force the builder stage to execute natively on host CPU (x86_64 / amd64)
FROM --platform=$BUILDPLATFORM golang:1.25 AS builder

# Automatically provided by Docker Buildx
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Copy Go module manifests and download dependencies natively
COPY go.mod go.sum ./
RUN go mod download

# Copy the Go source
COPY cmd/main.go cmd/main.go
COPY api/ api/
COPY internal/ internal/

# 2. Native Go cross-compilation (Runs in seconds on host hardware)
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -a -o manager cmd/main.go

# Minimal runtime image stage
FROM registry.access.redhat.com/ubi9/ubi-micro:latest
LABEL name="HariKube Serverless Kube Trigger"
LABEL vendor="inspirNation Bt."
LABEL version="beta-v1.0.0-8"
LABEL release="0"
LABEL summary="Declarative serverless function, AI model, or anything trigger"
LABEL description="Trigger your services based on state changes of Kubernetes API"
LABEL maintainer="richard.kovacs@harikube.com"

COPY LICENSE /licenses/LICENSE
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532

ENTRYPOINT ["/manager"]