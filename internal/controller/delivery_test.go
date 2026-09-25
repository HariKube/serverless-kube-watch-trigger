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
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
)

var _ = Describe("retryBackoff", func() {
	backoff := retryBackoff{min: time.Second, max: 30 * time.Second}

	It("returns zero for the initial attempt and grows exponentially", func() {
		Expect(backoff.delay(0)).To(Equal(time.Duration(0)))
		Expect(backoff.delay(1)).To(Equal(time.Second))
		Expect(backoff.delay(2)).To(Equal(2 * time.Second))
		Expect(backoff.delay(3)).To(Equal(4 * time.Second))
		Expect(backoff.delay(4)).To(Equal(8 * time.Second))
	})

	It("caps the delay at the configured maximum", func() {
		for attempt := 4; attempt < 20; attempt++ {
			Expect(backoff.delay(attempt)).To(BeNumerically("<=", 30*time.Second))
		}
		Expect(backoff.delay(20)).To(Equal(30 * time.Second))
	})

	It("returns zero for a zero minimum", func() {
		Expect((retryBackoff{min: 0, max: time.Second}).delay(1)).To(Equal(time.Duration(0)))
	})
})

var _ = Describe("deliveryGate", func() {
	It("does not delay below the failure threshold", func() {
		gate := newDeliveryGate(3, time.Second, 30*time.Second)

		Expect(gate.delay()).To(Equal(time.Duration(0)))
		gate.recordFailure()
		gate.recordFailure()
		Expect(gate.delay()).To(Equal(time.Duration(0)))

		// Crossing the threshold starts the backoff.
		gate.recordFailure()
		Expect(gate.delay()).To(Equal(time.Second))
	})

	It("grows the delay exponentially and caps it", func() {
		gate := newDeliveryGate(1, time.Second, 30*time.Second)

		gate.recordFailure()
		Expect(gate.delay()).To(Equal(time.Second))

		gate.recordFailure()
		Expect(gate.delay()).To(Equal(2 * time.Second))

		for i := 0; i < 20; i++ {
			gate.recordFailure()
		}
		Expect(gate.delay()).To(Equal(30 * time.Second))
	})

	It("resets to no delay after a successful delivery", func() {
		gate := newDeliveryGate(1, time.Second, 30*time.Second)

		gate.recordFailure()
		Expect(gate.delay()).ToNot(BeZero())

		gate.recordSuccess()
		Expect(gate.delay()).To(Equal(time.Duration(0)))
		Expect(gate.consecutiveFailures()).To(Equal(0))
	})

	It("tracks the consecutive failure count", func() {
		gate := newDeliveryGate(3, time.Second, 30*time.Second)
		Expect(gate.consecutiveFailures()).To(Equal(0))

		gate.recordFailure()
		gate.recordFailure()
		gate.recordFailure()
		Expect(gate.consecutiveFailures()).To(Equal(3))
	})

	It("is safe to use concurrently", func() {
		gate := newDeliveryGate(1, time.Millisecond, time.Millisecond)
		var done atomic.Bool

		for i := 0; i < 10; i++ {
			go func() {
				defer GinkgoRecover()

				for !done.Load() {
					_ = gate.delay()
					gate.consecutiveFailures()
					gate.recordFailure()
					gate.recordSuccess()
				}
			}()
		}

		time.Sleep(50 * time.Millisecond)
		done.Store(true)
	})
})

var _ = Describe("deliveryGateRegistry", func() {
	It("creates, reuses and removes gates per trigger", func() {
		reg := &deliveryGateRegistry{}

		gate := reg.get("default/foo")
		gate.recordFailure()
		Expect(reg.get("default/foo")).To(BeIdenticalTo(gate))
		Expect(reg.get("default/foo").consecutiveFailures()).To(Equal(1))

		Expect(reg.get("default/bar")).NotTo(BeIdenticalTo(gate))

		reg.remove("default/foo")
		Expect(reg.get("default/foo")).NotTo(BeIdenticalTo(gate))

		reg.clear()
		Expect(reg.get("default/bar")).NotTo(BeIdenticalTo(gate))
	})
})

var _ = Describe("deliverPayload", func() {
	const (
		kind      = kindHTTPTrigger
		method    = "POST"
		timeout   = time.Second
		eventType = "MODIFIED"
	)

	metadata := map[string]interface{}{
		"name":            "source",
		"namespace":       "default",
		"resourceVersion": "42",
	}

	var (
		ctx    context.Context
		cancel context.CancelFunc
		client *http.Client
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())
		client = &http.Client{Timeout: timeout}
	})

	AfterEach(func() {
		cancel()
	})

	It("returns true on a 2xx response", func() {
		trigger := "default/test-success"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		ok, err := deliverPayload(ctx, logr.Discard(), client, kind, trigger, method, srv.URL, "body", nil, nil, "", 1, timeout, retryBackoff{min: time.Millisecond, max: time.Millisecond}, eventType, metadata)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())

		Expect(testutil.ToFloat64(deliveryCallsTotal.WithLabelValues(kind, trigger, method, metricResultSuccess, "204"))).To(Equal(float64(1)))
		Expect(testutil.ToFloat64(deliveryCallsFailedTotal.WithLabelValues(kind, trigger, method, metricFailureReasonStatus))).To(Equal(float64(0)))
	})

	It("retries with backoff until the endpoint recovers", func() {
		trigger := "default/test-retry"
		attempts := atomic.Int32{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if attempts.Add(1) < 3 {
				w.WriteHeader(http.StatusInternalServerError)

				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		start := time.Now()
		ok, err := deliverPayload(ctx, logr.Discard(), client, kind, trigger, method, srv.URL, "body", nil, nil, "", 5, timeout, retryBackoff{min: time.Millisecond, max: 5 * time.Millisecond}, eventType, metadata)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(time.Since(start)).To(BeNumerically("<", time.Second))
		Expect(attempts.Load()).To(Equal(int32(3)))
		Expect(testutil.ToFloat64(deliveryRetriesTotal.WithLabelValues(kind, trigger, method, metricResultError))).To(Equal(float64(2)))
	})

	It("returns the last error and records metrics when retries are exhausted", func() {
		trigger := "default/test-exhausted"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		ok, err := deliverPayload(ctx, logr.Discard(), client, kind, trigger, method, srv.URL, "body", nil, nil, "", 2, timeout, retryBackoff{min: time.Millisecond, max: time.Millisecond}, eventType, metadata)
		Expect(ok).To(BeFalse())
		Expect(err).To(MatchError("status code is 503"))

		Expect(testutil.ToFloat64(deliveryCallsTotal.WithLabelValues(kind, trigger, method, metricResultError, "503"))).To(Equal(float64(3)))
		Expect(testutil.ToFloat64(deliveryCallsFailedTotal.WithLabelValues(kind, trigger, method, metricFailureReasonStatus))).To(Equal(float64(3)))
		Expect(testutil.ToFloat64(deliveryRetriesTotal.WithLabelValues(kind, trigger, method, metricResultError))).To(Equal(float64(2)))
	})

	It("records transport failures separately", func() {
		trigger := "default/test-transport"
		// Port 1 is virtually guaranteed to refuse the connection.
		ok, err := deliverPayload(ctx, logr.Discard(), client, kind, trigger, method, "http://127.0.0.1:1/hook", "body", nil, nil, "", 0, timeout, retryBackoff{min: time.Millisecond, max: time.Millisecond}, eventType, metadata)
		Expect(ok).To(BeFalse())
		Expect(err).To(HaveOccurred())

		Expect(testutil.ToFloat64(deliveryCallsTotal.WithLabelValues(kind, trigger, method, metricResultError, "0"))).To(Equal(float64(1)))
		Expect(testutil.ToFloat64(deliveryCallsFailedTotal.WithLabelValues(kind, trigger, method, metricFailureReasonRequest))).To(Equal(float64(1)))
	})

	It("sets basic auth credentials when configured", func() {
		gotAuth := make(chan string, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth <- r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		basicAuth := &triggersv1.BasicAuth{User: "user"}
		ok, err := deliverPayload(ctx, logr.Discard(), client, kind, "default/test-basic-auth", method, srv.URL, "body", nil, basicAuth, "password", 0, timeout, retryBackoff{}, eventType, metadata)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(<-gotAuth).To(Equal("Basic dXNlcjpwYXNzd29yZA=="))
	})

	It("does not set basic auth when not configured", func() {
		gotAuth := make(chan string, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth <- r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		ok, err := deliverPayload(ctx, logr.Discard(), client, kind, "default/test-no-auth", method, srv.URL, "body", nil, nil, "", 0, timeout, retryBackoff{}, eventType, metadata)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(<-gotAuth).To(Equal(""))
	})

	It("aborts retries when the context is cancelled", func() {
		trigger := "default/test-cancelled"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		cancel()

		ok, err := deliverPayload(ctx, logr.Discard(), client, kind, trigger, method, srv.URL, "body", nil, nil, "", 10, time.Millisecond, retryBackoff{min: time.Second, max: time.Second}, eventType, metadata)
		Expect(ok).To(BeFalse())
		Expect(err).To(HaveOccurred())
	})
})
