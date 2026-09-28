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
	"net"
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

	metricControllerHTTPTrigger  = "httptrigger"
	metricControllerPiTrigger    = "pitrigger"
	metricControllerPiTriggerJob = "pitrigger-job"
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

	// A stable, small-cardinality classification of HTTP/transport failures used
	// for richer observability without exposing raw error strings.
	deliveryCallsFailedClassTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: "delivery",
		Name:      "calls_failed_class_total",
		Help:      "Total number of failed endpoint calls classified by stable error class (network, timeout, client_error, server_error, unknown).",
	}, []string{"kind", "trigger", "method", "class"})

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

	controllersRunning = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: "runtime",
		Name:      "controllers_running",
		Help:      "Number of active controller sessions or controller workers currently running, by controller.",
	}, []string{"controller"})

	reconcilesRunning = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: "runtime",
		Name:      "reconciles_running",
		Help:      "Number of in-flight reconcile calls currently running, by controller.",
	}, []string{"controller"})

	watcherGoroutinesRunning = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: "runtime",
		Name:      "watcher_goroutines_running",
		Help:      "Number of watcher goroutines currently running, by controller.",
	}, []string{"controller"})

	piTriggerRunningJobs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: "runtime",
		Name:      "pitrigger_jobs_running",
		Help:      "Number of Pi worker Jobs currently running or reserved for dispatch, per trigger.",
	}, []string{"trigger"})

	// PiTrigger job lifecycle metrics: durations, terminal outcomes and requeues.
	pitriggerJobDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Subsystem: "pitrigger",
		Name:      "job_duration_seconds",
		Help:      "Duration of PiTrigger worker Jobs from dispatch to terminal state, in seconds.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"trigger", "outcome"})

	pitriggerJobTerminalsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: "pitrigger",
		Name:      "job_terminals_total",
		Help:      "Counts of PiTrigger job terminal outcomes (success, error) and stable reason classifications.",
	}, []string{"trigger", "outcome", "reason"})

	pitriggerJobRequeuesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: "pitrigger",
		Name:      "job_requeues_total",
		Help:      "Number of times PiTrigger jobs were requeued for processing, by stable reason.",
	}, []string{"trigger", "reason"})
)

func init() {
	crmetrics.Registry.MustRegister(
		deliveryCallsTotal,
		deliveryCallsFailedTotal,
		deliveryCallsFailedClassTotal,
		deliveryCallDurationSeconds,
		deliveryRetriesTotal,
		deliveryBackoffsTotal,
		controllersRunning,
		reconcilesRunning,
		watcherGoroutinesRunning,
		piTriggerRunningJobs,
		pitriggerJobDurationSeconds,
		pitriggerJobTerminalsTotal,
		pitriggerJobRequeuesTotal,
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

func recordControllerRegistered(controller string) {
	controllersRunning.WithLabelValues(controller).Set(1)
}

func recordControllerStopped(controller string) {
	controllersRunning.WithLabelValues(controller).Set(0)
	reconcilesRunning.WithLabelValues(controller).Set(0)
	watcherGoroutinesRunning.WithLabelValues(controller).Set(0)
}

func recordControllerSessionStart(controller string) {
	controllersRunning.WithLabelValues(controller).Inc()
}

func recordControllerSessionStop(controller string) {
	controllersRunning.WithLabelValues(controller).Dec()
}

func recordReconcileStart(controller string) {
	reconcilesRunning.WithLabelValues(controller).Inc()
}

func recordReconcileDone(controller string) {
	reconcilesRunning.WithLabelValues(controller).Dec()
}

func recordWatcherGoroutineStart(controller string) {
	watcherGoroutinesRunning.WithLabelValues(controller).Inc()
}

func recordWatcherGoroutineDone(controller string) {
	watcherGoroutinesRunning.WithLabelValues(controller).Dec()
}

func setPiTriggerRunningJobs(trigger string, running int) {
	piTriggerRunningJobs.WithLabelValues(trigger).Set(float64(running))
}

func deletePiTriggerRunningJobs(trigger string) {
	piTriggerRunningJobs.DeleteLabelValues(trigger)
}

// classifyHTTPError produces a small-cardinality, stable label describing the
// observable class of an HTTP/transport failure. Callers should pass the
// transport error (if any) and the HTTP status code when available. The
// function intentionally returns readable labels rather than raw error text to
// avoid label cardinality explosions.
func classifyHTTPError(err error, statusCode int) string {
	if err != nil {
		// network/timeout vs other request errors
		if ne, ok := err.(net.Error); ok {
			if ne.Timeout() {
				return "timeout"
			}
			return "network"
		}
		return "request_error"
	}
	// No transport error - classify by status code range.
	if statusCode >= 200 && statusCode < 300 {
		return metricResultSuccess
	} else if statusCode >= 400 && statusCode < 500 {
		return "client_error"
	} else if statusCode >= 500 && statusCode < 600 {
		return "server_error"
	}
	return "status_unknown"
}

// recordDeliveryHTTPClass increments the failure-class counter used for
// richer HTTP error observability.
func recordDeliveryHTTPClass(kind, trigger, method, class string) {
	deliveryCallsFailedClassTotal.WithLabelValues(kind, trigger, method, class).Inc()
}

// recordPiTriggerJobTerminal records a terminal outcome and duration when the
// caller already has a measured duration.
func recordPiTriggerJobTerminal(trigger, outcome, reason string, duration time.Duration) {
	pitriggerJobDurationSeconds.WithLabelValues(trigger, outcome).Observe(duration.Seconds())
	pitriggerJobTerminalsTotal.WithLabelValues(trigger, outcome, reason).Inc()
}

// recordPiTriggerJobRequeue records that a PiTrigger job was requeued with a
// small-cardinality reason label.
func recordPiTriggerJobRequeue(trigger, reason string) {
	pitriggerJobRequeuesTotal.WithLabelValues(trigger, reason).Inc()
}
