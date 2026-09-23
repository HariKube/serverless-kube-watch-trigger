# Build the manager binary
FROM golang:1.25 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/main.go cmd/main.go
COPY api/ api/
COPY internal/ internal/

# Build
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -a -o manager cmd/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
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
