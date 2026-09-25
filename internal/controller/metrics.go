/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	metricsNamespace = "serverless_kube_watch_trigger"

	metricResultSuccess = "success"
	metricResultError   = "error"

	metricFailureReasonRequest = "request"
	metricFailureReasonStatus  = "status"
)

// Per-trigger delivery metrics. They are registered on the controller-runtime
// registry so they are served on the manager's metrics endpoint alongside the
// standard controller metrics. The `trigger` label identifies a single
// trigger as "namespace/name", which makes the delivery outcome observable
// per trigger in addition to the Kubernetes Events emitted for each failure.
var (
	deliveryCallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: "delivery",
		Name:      "calls_total",
		Help:      "Total number of endpoint calls made by the operator, per trigger and outcome.",
	}, []string{"kind", "trigger", "method", "result", "status_code"})

	deliveryCallsFailedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: "delivery",
		Name:      "calls_failed_total",
		Help:      "Total number of failed endpoint calls made by the operator, per trigger and failure reason.",
	}, []string{"kind", "trigger", "method", "reason"})

	deliveryCallDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Subsystem: "delivery",
		Name:      "call_duration_seconds",
		Help:      "Duration of endpoint calls in seconds, per trigger and outcome.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"kind", "trigger", "method", "result"})

	deliveryRetriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: "delivery",
		Name:      "retries_total",
		Help:      "Total number of retry attempts performed before a call succeeded or was dropped.",
	}, []string{"kind", "trigger", "method", "result"})

	deliveryBackoffsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: "delivery",
		Name:      "backoffs_total",
		Help:      "Total number of times a delivery was delayed because the endpoint was under sustained failure.",
	}, []string{"kind", "trigger"})
)

func init() {
	crmetrics.Registry.MustRegister(
		deliveryCallsTotal,
		deliveryCallsFailedTotal,
		deliveryCallDurationSeconds,
		deliveryRetriesTotal,
		deliveryBackoffsTotal,
	)
}

// recordDeliveryCall records a single endpoint call: its outcome, status code
// and latency. Both the counter and the latency histogram are updated so a
// delivery outcome is fully observable per trigger.
func recordDeliveryCall(result string, statusCode int, latency time.Duration, kind, trigger, method string) {
	deliveryCallsTotal.WithLabelValues(kind, trigger, method, result, fmt.Sprint(statusCode)).Inc()
	deliveryCallDurationSeconds.WithLabelValues(kind, trigger, method, result).Observe(latency.Seconds())
}

// recordDeliveryFailure records a failed endpoint call together with the
// classifying failure reason.
func recordDeliveryFailure(kind, trigger, method, reason string) {
	deliveryCallsFailedTotal.WithLabelValues(kind, trigger, method, reason).Inc()
}

// recordDeliveryRetry records a single retry attempt.
func recordDeliveryRetry(kind, trigger, method, result string) {
	deliveryRetriesTotal.WithLabelValues(kind, trigger, method, result).Inc()
}

// recordDeliveryBackoff records a delivery that was delayed by the
// sustained-failure backoff strategy.
func recordDeliveryBackoff(kind, trigger string) {
	deliveryBackoffsTotal.WithLabelValues(kind, trigger).Inc()
}
