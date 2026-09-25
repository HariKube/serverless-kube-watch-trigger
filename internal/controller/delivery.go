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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
)

const (
	kindHTTPTrigger = "httptrigger"
	kindAITrigger   = "aitrigger"

	// defaultRetryBackoffMin is the initial delay observed between retry
	// attempts of a single delivery.
	defaultRetryBackoffMin = time.Second
	// defaultRetryBackoffMax caps the exponentially growing delay between
	// retry attempts of a single delivery.
	defaultRetryBackoffMax = 30 * time.Second

	// defaultGateFailureThreshold is the number of consecutive failed
	// deliveries after which the delivery gate starts delaying further
	// deliveries to protect an endpoint under sustained failure.
	defaultGateFailureThreshold = 3
	// defaultGateBackoffMin is the initial delay applied by the delivery gate.
	defaultGateBackoffMin = time.Second
	// defaultGateBackoffMax caps the exponentially growing gate delay.
	defaultGateBackoffMax = 30 * time.Second
)

// retryBackoff computes the exponentially growing delay to observe between
// retry attempts of a single delivery.
type retryBackoff struct {
	min time.Duration
	max time.Duration
}

// delay returns the delay to observe before attempt `attempt` (0-based). The
// first retry always waits min and every following retry doubles the wait up
// to max.
func (b retryBackoff) delay(attempt int) time.Duration {
	if attempt <= 0 || b.min <= 0 {
		return 0
	}

	delay := b.min
	for i := 1; i < attempt && delay < b.max; i++ {
		delay *= 2
	}
	if delay > b.max {
		delay = b.max
	}

	return delay
}

// deliveryGate implements the sustained-failure backoff strategy. It tracks
// consecutive delivery failures per trigger and, once the failure threshold
// is crossed, returns an exponentially growing delay that spaces out further
// deliveries to a failing endpoint. Any successful delivery resets the gate.
// The gate is stored on the reconciler keyed by trigger, so it survives
// watcher session restarts: a trigger that keeps failing will not hammer its
// endpoint across restart cycles.
type deliveryGate struct {
	mu               sync.Mutex
	consecutiveFails int
	threshold        int
	min              time.Duration
	max              time.Duration
}

func newDeliveryGate(threshold int, min, max time.Duration) *deliveryGate {
	return &deliveryGate{
		threshold: threshold,
		min:       min,
		max:       max,
	}
}

// delay returns the time the caller must hold off before the next delivery
// attempt. It is zero while the endpoint is healthy (or until the failure
// threshold is reached) and grows exponentially from min to max afterwards.
func (g *deliveryGate) delay() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.delayLocked()
}

func (g *deliveryGate) delayLocked() time.Duration {
	if g.threshold <= 0 || g.min <= 0 || g.consecutiveFails < g.threshold {
		return 0
	}

	steps := g.consecutiveFails - g.threshold + 1
	delay := g.min
	for i := 1; i < steps && delay < g.max; i++ {
		delay *= 2
	}
	if delay > g.max {
		delay = g.max
	}

	return delay
}

// consecutiveFailures returns the current number of consecutive failed
// deliveries.
func (g *deliveryGate) consecutiveFailures() int {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.consecutiveFails
}

// recordSuccess resets the failure counter after a successful delivery.
func (g *deliveryGate) recordSuccess() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.consecutiveFails = 0
}

// recordFailure increments the consecutive failure counter after a failed
// delivery.
func (g *deliveryGate) recordFailure() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.consecutiveFails++
}

// deliveryGateRegistry owns one deliveryGate per trigger. Entries persist
// across watcher session restarts so the backoff protects endpoints under
// sustained failure and are cleaned up when a trigger is deleted.
type deliveryGateRegistry struct {
	mu    sync.Mutex
	gates map[string]*deliveryGate
}

func (r *deliveryGateRegistry) init() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.gates == nil {
		r.gates = map[string]*deliveryGate{}
	}
}

// get returns the gate for the given trigger, creating it on first use.
func (r *deliveryGateRegistry) get(key string) *deliveryGate {
	r.init()

	r.mu.Lock()
	defer r.mu.Unlock()

	if gate, ok := r.gates[key]; ok {
		return gate
	}

	gate := newDeliveryGate(defaultGateFailureThreshold, defaultGateBackoffMin, defaultGateBackoffMax)
	r.gates[key] = gate

	return gate
}

// remove drops the gate for a deleted trigger so the registry never leaks.
func (r *deliveryGateRegistry) remove(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.gates, key)
}

// clear drops all gates; used on manager shutdown.
func (r *deliveryGateRegistry) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.gates = map[string]*deliveryGate{}
}

// sleepContext waits for the given duration or returns false as soon as the
// context is done, so shutdown is never blocked by a backoff sleep.
func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// deliverPayload performs up to retries+1 attempts to call the configured
// endpoint, backing off exponentially between attempts and recording
// per-trigger delivery metrics. It returns true when an attempt received a
// 2xx response and the error of the last failed attempt otherwise.

func deliverPayload(
	ctx context.Context,
	logger logr.Logger,
	httpClient *http.Client,
	kind, triggerRefName, method, url string,
	body string,
	headers map[string]string,
	basicAuth *triggersv1.BasicAuth,
	basicAuthPassword string,
	retries uint8,
	timeout time.Duration,
	backoff retryBackoff,
	eventType string,
	metadata map[string]interface{},
) (bool, error) {
	var retryErr error

	for attempt := 0; attempt <= int(retries); attempt++ {
		attemptStart := time.Now()

		reqCtx, reqCancel := context.WithTimeout(ctx, normalizeHTTPTimeout(timeout))

		req, err := http.NewRequestWithContext(reqCtx, method, url, strings.NewReader(body))
		if err != nil {
			reqCancel()

			return false, err
		}

		if basicAuth != nil {
			req.SetBasicAuth(basicAuth.User, basicAuthPassword)
		}

		for k, v := range headers {
			req.Header.Add(k, v)
		}

		resp, err := httpClient.Do(req)
		latency := time.Since(attemptStart)
		reqCancel()

		if err != nil {
			recordDeliveryCall(metricResultError, 0, latency, kind, triggerRefName, method)
			recordDeliveryFailure(kind, triggerRefName, method, metricFailureReasonRequest)
			logger.Error(err, "Endpoint call failed", "name", metadata["name"], "namespace", metadata["namespace"], "resourceVersion", metadata["resourceVersion"])

			retryErr = err

			reqCancel()

			if attempt < int(retries) {
				recordDeliveryRetry(kind, triggerRefName, method, metricResultError)
				if !sleepContext(ctx, backoff.delay(attempt)) {
					return false, retryErr
				}
			}

			continue
		} else if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if resp == nil {
				retryErr = errors.New("missing response")
			} else {
				retryErr = fmt.Errorf("status code is %d", resp.StatusCode)
			}

			recordDeliveryCall(metricResultError, resp.StatusCode, latency, kind, triggerRefName, method)
			recordDeliveryFailure(kind, triggerRefName, method, metricFailureReasonStatus)
			logger.Error(retryErr, "Endpoint call failed", "name", metadata["name"], "namespace", metadata["namespace"], "resourceVersion", metadata["resourceVersion"])

			reqCancel()
			if err := resp.Body.Close(); err != nil {
				logger.Error(err, "Failed to close response body")

				return false, retryErr
			}

			if attempt < int(retries) {
				recordDeliveryRetry(kind, triggerRefName, method, metricResultError)
				if !sleepContext(ctx, backoff.delay(attempt)) {
					return false, retryErr
				}
			}

			continue
		}

		recordDeliveryCall(metricResultSuccess, resp.StatusCode, latency, kind, triggerRefName, method)
		logger.Info("Endpoint successfully called", "name", metadata["name"], "namespace", metadata["namespace"], "resourceVersion", metadata["resourceVersion"], "eventType", eventType)

		reqCancel()
		if err := resp.Body.Close(); err != nil {
			logger.Error(err, "Failed to close response body")

			return false, retryErr
		}

		return true, nil
	}

	return false, retryErr
}
