# serverless-kube-watch-trigger
A lightweight Kubernetes operator that turns **Kubernetes API server watch events into trigger sources** for serverless functions and external systems. It allows you to declaratively define *when* and *how* functions or webhooks should fire in response to changes in Kubernetes resources — without modifying the API server or deploying heavy eventing frameworks.

## Description
`Serverless-kube-watch-trigger` bridges the gap between **Kubernetes-native resource events** and **serverless workloads**.  
At its core, it watches selected Kubernetes resources (built-in or CRDs) using efficient watch streams, and then dispatches structured trigger events based on user-defined specifications. These triggers can launch serverless functions (e.g. OpenFaaS, Knative), send webhooks, or integrate with external systems such as CI/CD pipelines or monitoring tools.

## Installation

Please follow the guide in the [release](https://github.com/HariKube/serverless-kube-watch-trigger/releases) section.

## Getting Started

### 📌 Overview

An `HTTPTrigger` watches a target Kubernetes resource (e.g., `Deployment` or any other Custom Resources), filters events, and sends HTTP requests when matching events happen.

Each trigger consists of:

* **Resource selector** (what to watch)
* **Event filters** (when to trigger)
* **Endpoint configuration** (where to send)
* **Auth / Headers / Body** configuration (what to send)
* **Delivery policies** (how to deliver)

---

### 🧱 Example

```yaml
apiVersion: triggers.example.com/v1
kind: HTTPTrigger
metadata:
  name: full-httptrigger-example
  namespace: default
spec:
  resource:
    apiVersion: apps/v1
    kind: Deployment
  namespaces: # Optional
    - default
    - kube-system
  labelSelectors: # Optional
    - app=frontend
    - tier=prod
  fieldSelectors: # Optional
    - metadata.name=my-deployment
  eventTypes: # Optional
    - ADDED
    - MODIFIED
    - DELETED
  eventFilter: 'ne .status.availableReplicas 0' # Optional
  concurrency: 5 # Optional
  sendInitialEvents: false # Optional

  # --- Endpoint ---
  url: # Select one option
    static: "https://example.com/hook"
    # template: "https://example.com/hook/{{ .metadata.name }}"
    # service:
    #   name: webhook-svc
    #   namespace: default
    #   portName: https # Optional
    #   scheme: https # Optional 
    #   uri:
    #     template: "/hook/{{ .metadata.name }}"
  method: POST # Optional

  # --- Authentication ---
  auth:
    basicAuth: # Optional
      user: ci-bot
      secretKeyRef:
        name: webhook-pass
        key: password
    tls: # Optional
      caRef:
        name: webhook-ca
        key: ca.crt
      certRef:
        name: webhook-cert
        key: tls.crt
      keyRef:
        name: webhook-cert
        key: tls.key
      insecureSkipVerify: false

  # --- Headers ---
  headers:
    static: # Optional
      X-Static-Token: "fixed-token-value"
      X-Cluster-ID: "cluster-001"
    template: # Optional
      X-Resource-Name: "{{ .metadata.name }}"
      X-Resource-Namespace: "{{ .metadata.namespace }}"
    fromSecretRef: # Optional
      X-Api-Key:
        name: api-secret
        key: api-key
      X-Other-Token:
        name: extra-secrets
        key: token

  # --- Body ---
  body:
    contentType: application/json # Optional
    template: | # Optional
      {{ toJson . }}
    signature: # Optional
      header: X-Signature
      keySecretRef:
        name: sig-key
        key: key
      hmac:
        hashType: SHA512

  # --- Delivery ---
  delivery:
    timeout: 30s # Optional
    retries: 5 # Optional
```

---

### 🖍 Spec Details

#### 🎯 **Resource Selection**

| Field               | Description                                                                            |
| ------------------- | -------------------------------------------------------------------------------------- |
| `resource`          | Target resource kind + API version to watch.                                           |
| `namespaces`        | List of namespaces to watch.                                                           |
| `labelSelectors`    | Optional label selectors to filter resources.                                          |
| `fieldSelectors`    | Optional field selectors to filter resources.                                          |
| `eventTypes`        | Which events to trigger on (`ADDED`, `MODIFIED`, `DELETED`).                           |
| `eventFilter`       | Go template expression evaluated on objects. Return true to trigger. |
| `concurrency`       | Max parallel triggers.                                                                 |
| `sendInitialEvents` | Whether to emit initial events for existing objects.                                   |

---

#### 🌐 **Endpoint**

One of:

* `url.static` – fixed URL
* `url.template` – URL template with Go template syntax
* `url.service` – service name + optional URI strategy (static/template)

`method` defines the HTTP verb (default: `POST`).

---

#### 🔐 **Authentication**

Under `auth`, you may configure one or more of:

* `basicAuth`:
  Uses username and password from a secret key reference.

* `tls`:
  mTLS configuration with CA, client cert, and key references.

---

#### 📨 **Headers**

Headers can be defined in three ways:

* `static`: fixed key/value pairs
* `template`: dynamic values using Go templates
* `fromSecretRef`: load header values from Kubernetes secrets

---

#### 🧰 **Body**

Controls the request payload.

| Field         | Description                                                                             |
| ------------- | --------------------------------------------------------------------------------------- |
| `contentType` | Content type of the body (default: `application/json`).                                 |
| `template`    | Go template to generate the request body. `{{ toJson . }}` dumps the full event object. |
| `signature`   | Optional HMAC or static signature added to a header.                                    |

---

#### 🚚 **Delivery**

| Field     | Description                             |
| --------- | --------------------------------------- |
| `timeout` | Maximum request duration (default: `10s`). |
| `retries` | Number of retry attempts on failure.    |

---

### ⚡ Usage Tips

* Use `{{ toJson . }}` to include the **entire event** as JSON in the body.
* Combine `eventFilter` with label/field selectors for fine-grained control.
* TLS and BasicAuth can be used together if the target requires both mutual TLS and credentials.
* Upon any error, the operator first updates the trigger's status field. It then tries to restart the watcher, resuming from the status.lastResourceVersion.

---

### 🚀 Apply the Trigger

```bash
kubectl apply -f full-httptrigger-example.yaml
```

Then modify or create a matching `Deployment` — the webhook endpoint will receive JSON payloads for every matching event.

---

### 🧪 Debugging

* Use `kubectl describe httptrigger <name>` to see status and events.
* Check logs of the controller that processes `HTTPTrigger` resources.
* Use `toPrettyJson` in templates to make payloads human-readable during testing.

## Development

### Prerequisites
- go version v1.24.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/serverless-kube-watch-trigger:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/serverless-kube-watch-trigger:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following the options to release and provide this solution to the users.

### By providing a bundle with all YAML files

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/serverless-kube-watch-trigger:tag
```

**NOTE:** The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without its
dependencies.

2. Using the installer

Users can just run 'kubectl apply -f <URL for YAML BUNDLE>' to install
the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/serverless-kube-watch-trigger/<tag or branch>/dist/install.yaml
```

### By providing a Helm Chart

1. Build the chart using the optional helm plugin

```sh
kubebuilder edit --plugins=helm/v1-alpha
```

2. See that a chart was generated under 'dist/chart', and users
can obtain this solution from there.

**NOTE:** If you change the project, you need to update the Helm Chart
using the same command above to sync the latest changes. Furthermore,
if you create webhooks, you need to use the above command with
the '--force' flag and manually ensure that any custom configuration
previously added to 'dist/chart/values.yaml' or 'dist/chart/manager/manager.yaml'
is manually re-applied afterwards.

## 🤝 Contribution Guide

We welcome and encourage contributions from the community! Whether it's a bug fix, a new feature, or an improvement to the documentation, your help is greatly appreciated.

Before you get started, please take a moment to review our guidelines:

- Read the Documentation: Familiarize yourself with the framework's architecture and existing features.
- Open an Issue: For any significant changes or new features, please open an issue first to discuss the idea. This helps prevent duplicated work and ensures alignment with the project's goals.
- Fork the Repository: Fork the repository to your own GitHub account.
- Create a Branch: Create a new branch for your feature or bug fix: git checkout -b feature-my-awesome-feature.
- Commit Your Changes: Make your changes and commit them with a clear and descriptive message.
- Submit a Pull Request: Push your branch to your forked repository and open a pull request against the main branch of this repository. Please provide a clear description of your changes in the PR.

We are committed to providing a friendly, safe, and welcoming environment for all, regardless of background or experience. We are following Kubernetes Please see them [Code of Conduct](https://kubernetes.io/community/code-of-conduct/) for more details.

## 🙏 Share Feedback and Report Issues

Your feedback is invaluable in helping us improve this framework. If you encounter any issues, have a suggestion for a new feature, or simply want to share your experience, we want to hear from you!

- Report Bugs: If you find a bug, please open a [GitHub Issue](https://github.com/HariKube/serverless-kube-watch-trigger/issues). Include as much detail as possible, such as steps to reproduce the bug, expected behavior, and your environment (e.g., Kubernetes version, Go version).
- Request a Feature: If you have an idea for a new feature, open a [GitHub Issue](https://github.com/HariKube/serverless-kube-watch-trigger/issues) and use the feature request label. Describe the use case and how the new feature would benefit the community.
- Ask a Question: For general questions or discussions, please use the [GitHub Discussions](https://github.com/HariKube/serverless-kube-watch-trigger/discussions).

## 📝 License

This project is licensed under the BSD 3-Clause "New" or "Revised" License. See the LICENSE file for details.

## ✨ Special Thanks

We'd like to extend our gratitude to the Kubernetes community and the developers of related projects like controller-runtime and kubebuilder for their foundational work that inspired and enabled the creation of this framework.

