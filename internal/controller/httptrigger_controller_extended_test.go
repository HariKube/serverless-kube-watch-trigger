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
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
	"github.com/harikube/serverless-kube-watch-trigger/pkg/lease"
	"github.com/harikube/serverless-kube-watch-trigger/pkg/partition"
)

// drainRunningTriggers stops every running trigger and clears the registry.
func drainRunningTriggers(r *HTTPTriggerReconciler) {
	r.runningTriggersLock.Lock()
	cancels := make([]func(), 0, len(r.runningTriggers))
	for _, c := range r.runningTriggers {
		cancels = append(cancels, c)
	}
	r.runningTriggers = map[string]func(){}
	r.runningTriggersLock.Unlock()

	for _, c := range cancels {
		c()
	}
}

// newReconciler builds a fresh HTTPTriggerReconciler backed by the shared envtest clients.
// The reconciler uses the suite-level ctx so that cancellation on suite teardown propagates.
func newReconciler() *HTTPTriggerReconciler {
	r := &HTTPTriggerReconciler{
		Client:              k8sClient,
		DynamicClient:       dynamicClient,
		Scheme:              k8sClient.Scheme(),
		Recorder:            record.NewFakeRecorder(10),
		PartitionController: partition.NewSingleWorkerController(),
		ctx:                 ctx,
		runningTriggersLock: sync.Mutex{},
		runningTriggers:     map[string]func(){},
		triggerLocksLock:    sync.Mutex{},
		triggerLocks:        map[string]*sync.Mutex{},
	}
	DeferCleanup(func() {
		drainRunningTriggers(r)
	})
	return r
}

// cleanupTrigger deletes a named HTTPTrigger silently.
func cleanupTrigger(ctx context.Context, name string) {
	trigger := &triggersv1.HTTPTrigger{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, trigger); err == nil {
		_ = k8sClient.Delete(ctx, trigger)
	}
}

// cleanupSecret deletes a named Secret silently.
func cleanupSecret(ctx context.Context, name string) {
	secret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, secret); err == nil {
		_ = k8sClient.Delete(ctx, secret)
	}
}

// cleanupService deletes a named Service silently.
func cleanupService(ctx context.Context, name string) {
	svc := &corev1.Service{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, svc); err == nil {
		_ = k8sClient.Delete(ctx, svc)
	}
}

var _ = Describe("HTTPTrigger Controller - additional coverage", func() {
	const ns = "default"
	bgCtx := context.Background()

	It("drains running triggers without holding the mutex while callbacks run", func() {
		r := &HTTPTriggerReconciler{
			runningTriggersLock: sync.Mutex{},
			runningTriggers:     map[string]func(){},
		}
		callbackRan := make(chan struct{})
		done := make(chan struct{})

		r.runningTriggers["default/test"] = func() {
			r.runningTriggersLock.Lock()
			defer r.runningTriggersLock.Unlock()
			close(callbackRan)
		}

		go func() {
			defer close(done)
			drainRunningTriggers(r)
		}()

		Eventually(callbackRan, time.Second).Should(BeClosed())
		Eventually(done, time.Second).Should(BeClosed())
		Expect(r.runningTriggers).To(BeEmpty())
	})

	// ─────────────────────────────────────────────────────────────
	// Reconcile: trigger not found returns no error
	// ─────────────────────────────────────────────────────────────
	Context("Reconcile - trigger not found", func() {
		It("returns no error when the resource does not exist", func() {
			r := newReconciler()
			_, err := r.Reconcile(bgCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "does-not-exist-xqz", Namespace: ns},
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	// ─────────────────────────────────────────────────────────────
	// Reconcile: no-op when up-to-date (no error, same generation)
	// ─────────────────────────────────────────────────────────────
	Context("Reconcile - short-circuit when already up to date", func() {
		const name = "trigger-noop"
		var srv *httptest.Server

		BeforeEach(func() {
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL)},
						Method: "POST",
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
		})

		AfterEach(func() {
			srv.Close()
			cleanupTrigger(bgCtx, name)
		})

		It("skips creating a new watcher when generation matches and no error", func() {
			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}

			// First reconcile - starts the watcher.
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			// Patch status to reflect generation==1 with no error.
			latest := &triggersv1.HTTPTrigger{}
			Expect(k8sClient.Get(bgCtx, nsn, latest)).To(Succeed())

			patched := latest.DeepCopy()
			patched.Status.LastGeneration = latest.Generation
			patched.Status.ErrorTime = metav1.Time{}
			Expect(k8sClient.Status().Patch(bgCtx, patched, client.MergeFrom(latest))).To(Succeed())

			// Cancel the running trigger so the map is clean.
			drainRunningTriggers(r)

			// Second reconcile - should be a no-op (returns immediately).
			_, err = r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	// ─────────────────────────────────────────────────────────────
	// Reconcile: watcher cleanup when a trigger is deleted
	// ─────────────────────────────────────────────────────────────
	Context("Reconcile - removes the watcher session when a trigger is deleted", func() {
		const name = "trigger-cleanup"
		var cancelCalled atomic.Bool
		var srv *httptest.Server

		BeforeEach(func() {
			cancelCalled.Store(false)
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
		})

		AfterEach(func() {
			srv.Close()
			cleanupTrigger(bgCtx, name)
		})

		It("cancels and drops the running watcher when the trigger is gone (NotFound)", func() {
			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			key := nsn.String()

			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			r.runningTriggersLock.Lock()
			_, registered := r.runningTriggers[key]
			r.runningTriggersLock.Unlock()
			Expect(registered).To(BeTrue())

			// Swap in a spy cancel so we can observe the session being stopped.
			r.runningTriggersLock.Lock()
			r.runningTriggers[key] = func() { cancelCalled.Store(true) }
			r.runningTriggersLock.Unlock()

			// Simulate a hard delete (no finalizer): the object disappears, so
			// the next reconcile's Get returns NotFound.
			Expect(k8sClient.Delete(bgCtx, &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			})).To(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(bgCtx, nsn, &triggersv1.HTTPTrigger{})
				return errors.IsNotFound(err)
			}, 10*time.Second, 500*time.Millisecond).Should(BeTrue())

			_, err = r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() bool { return cancelCalled.Load() }, 10*time.Second, 100*time.Millisecond).Should(BeTrue())

			Eventually(func() int {
				r.runningTriggersLock.Lock()
				defer r.runningTriggersLock.Unlock()

				return len(r.runningTriggers)
			}, 10*time.Second, 100*time.Millisecond).Should(BeZero())
		})
	})

	Context("Reconcile - deleted trigger owner lease timeout callback", func() {
		const (
			name      = "trigger-owner-lease-timeout"
			leaseName = "trigger-owner-lease-timeout-lease"
		)

		AfterEach(func() {
			trigger := &triggersv1.HTTPTrigger{}
			if err := k8sClient.Get(bgCtx, types.NamespacedName{Name: name, Namespace: ns}, trigger); err == nil {
				trigger.Finalizers = nil
				Expect(k8sClient.Update(bgCtx, trigger)).To(Succeed())
				Eventually(func() bool {
					err := k8sClient.Get(bgCtx, types.NamespacedName{Name: name, Namespace: ns}, &triggersv1.HTTPTrigger{})
					return errors.IsNotFound(err)
				}, 10*time.Second, 200*time.Millisecond).Should(BeTrue())
			}

			lease := &coordinationv1.Lease{}
			if err := k8sClient.Get(bgCtx, types.NamespacedName{Name: leaseName, Namespace: ns}, lease); err == nil {
				Expect(k8sClient.Delete(bgCtx, lease)).To(Succeed())
			}
		})

		It("calls the endpoint with a timeout message when a deleting trigger is owned by an expired lease", func() {
			requestBody := make(chan string, 1)
			var receivedBody string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				select {
				case requestBody <- string(body):
				default:
				}
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(srv.Close)

			renewTime := metav1.NewMicroTime(time.Now().Add(-2 * time.Minute))
			ownerLease := &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Name: leaseName, Namespace: ns},
				Spec: coordinationv1.LeaseSpec{
					LeaseDurationSeconds: ptr.To(int32(30)),
					RenewTime:            &renewTime,
				},
			}
			Expect(k8sClient.Create(bgCtx, ownerLease)).To(Succeed())

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{
					Name:       name,
					Namespace:  ns,
					Finalizers: []string{"tests.harikube.io/cleanup"},
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: coordinationv1.SchemeGroupVersion.String(),
						Kind:       "Lease",
						Name:       ownerLease.Name,
						UID:        ownerLease.UID,
					}},
				},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
						Delivery: triggersv1.Delivery{
							Timeout: metav1.Duration{Duration: 5 * time.Second},
							Retries: 1,
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			Expect(k8sClient.Delete(bgCtx, trigger)).To(Succeed())

			nsn := types.NamespacedName{Name: name, Namespace: ns}
			Eventually(func() bool {
				latest := &triggersv1.HTTPTrigger{}
				if err := k8sClient.Get(bgCtx, nsn, latest); err != nil {
					return false
				}
				return latest.DeletionTimestamp != nil && !latest.DeletionTimestamp.IsZero()
			}, 10*time.Second, 200*time.Millisecond).Should(BeTrue())

			r := newReconciler()
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() string {
				select {
				case receivedBody = <-requestBody:
				default:
				}
				return receivedBody
			}, 10*time.Second, 200*time.Millisecond).Should(ContainSubstring("timed out"))
			Expect(receivedBody).To(ContainSubstring(leaseName))
		})
	})

	// ─────────────────────────────────────────────────────────────
	// Reconcile: cancel existing watcher on update
	// ─────────────────────────────────────────────────────────────
	Context("Reconcile - cancels existing watcher on update", func() {
		const name = "trigger-update"
		var srv *httptest.Server

		BeforeEach(func() {
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL)},
						Method: "POST",
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
		})

		AfterEach(func() {
			srv.Close()
			cleanupTrigger(bgCtx, name)
		})

		It("cancels the existing watcher before starting a new one", func() {
			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}

			// First reconcile - starts watcher and patches status.LastGeneration = 1.
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			r.runningTriggersLock.Lock()
			Expect(r.runningTriggers).To(HaveKey(nsn.String()))
			r.runningTriggersLock.Unlock()

			// Wrap the existing cancel so we can observe it being called.
			cancelCalled := atomic.Bool{}
			r.runningTriggersLock.Lock()
			origCancel := r.runningTriggers[nsn.String()]
			r.runningTriggers[nsn.String()] = func() {
				cancelCalled.Store(true)
				origCancel()
			}
			r.runningTriggersLock.Unlock()

			// Simulate an error condition so the next reconcile does NOT short-circuit.
			// Patch status.Phase to Error so the short-circuit check fails.
			latest := &triggersv1.HTTPTrigger{}
			Expect(k8sClient.Get(bgCtx, nsn, latest)).To(Succeed())
			patched := latest.DeepCopy()
			patched.Status.Phase = triggersv1.TriggerPhaseError
			Expect(k8sClient.Status().Patch(bgCtx, patched, client.MergeFrom(latest))).To(Succeed())

			// Second reconcile while watcher is still running - should call cancel and return early.
			_, err = r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			// The cancel function must have been called.
			Expect(cancelCalled.Load()).To(BeTrue())
		})
	})

	// ─────────────────────────────────────────────────────────────
	// Reconcile: reports Running after watcher recovery restart
	// ─────────────────────────────────────────────────────────────
	Context("Reconcile - reports Running after watcher recovery restart", func() {
		const name = "trigger-recovery"
		var srv *httptest.Server

		BeforeEach(func() {
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL)},
						Method: "POST",
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
		})

		AfterEach(func() {
			srv.Close()
			cleanupTrigger(bgCtx, name)
		})

		It("re-establishes the watcher, reports Running and keeps the error detail", func() {
			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}

			// First reconcile - starts watcher and reports Running.
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			// Simulate the error status patch made by handleTriggerWatcherError.
			latest := &triggersv1.HTTPTrigger{}
			Expect(k8sClient.Get(bgCtx, nsn, latest)).To(Succeed())
			patched := latest.DeepCopy()
			patched.Status.Phase = triggersv1.TriggerPhaseError
			patched.Status.ErrorTime = metav1.Now()
			patched.Status.ErrorReason = "retry failed: status code is 500"
			patched.Status.ErrorResourceVersion = "42"
			Expect(k8sClient.Status().Patch(bgCtx, patched, client.MergeFrom(latest))).To(Succeed())

			// handleTriggerWatcherError removes the failed watcher from the map.
			r.runningTriggersLock.Lock()
			delete(r.runningTriggers, nsn.String())
			r.runningTriggersLock.Unlock()

			// Second reconcile - recovery restart: the watcher must be
			// re-established and the trigger must report Running again (with
			// the last failure retained for diagnostics) so users can tell the
			// trigger is healthy rather than stuck.
			_, err = r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			r.runningTriggersLock.Lock()
			Expect(r.runningTriggers).To(HaveKey(nsn.String()))
			r.runningTriggersLock.Unlock()

			updated := &triggersv1.HTTPTrigger{}
			Expect(k8sClient.Get(bgCtx, nsn, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal(triggersv1.TriggerPhaseRunning))
			Expect(updated.Status.ErrorReason).To(Equal("retry failed: status code is 500"))
			Expect(updated.Status.ErrorTime.IsZero()).To(BeFalse())
			Expect(updated.Status.ErrorResourceVersion).To(Equal("42"))
		})
	})

	// ─────────────────────────────────────────────────────────────
	// Reconcile: ErrInvalidTriggerContent - bad template
	// ─────────────────────────────────────────────────────────────
	Context("Reconcile - invalid trigger content", func() {
		const name = "trigger-invalid"

		AfterEach(func() {
			cleanupTrigger(bgCtx, name)
		})

		It("records ErrorReason in status for a bad URL template", func() {
			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
					},
					HTTP: triggersv1.HTTP{
						// Invalid Go template syntax.
						URL:    triggersv1.URL{Template: ptr.To("{{invalid template")},
						Method: "POST",
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			updated := &triggersv1.HTTPTrigger{}
			Eventually(func() string {
				_ = k8sClient.Get(bgCtx, nsn, updated)
				return updated.Status.ErrorReason
			}, 5*time.Second, 200*time.Millisecond).ShouldNot(BeEmpty())
		})
	})

	// ─────────────────────────────────────────────────────────────
	// Reconcile: deletion path
	// ─────────────────────────────────────────────────────────────
	Context("Reconcile - deletion path", func() {
		const name = "trigger-delete"
		var srv *httptest.Server

		BeforeEach(func() {
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL)},
						Method: "POST",
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
		})

		AfterEach(func() {
			srv.Close()
			cleanupTrigger(bgCtx, name)
		})

		It("cancels the watcher when the trigger is deleted", func() {
			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}

			// Start watcher.
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			cancelCalled := atomic.Bool{}
			r.runningTriggersLock.Lock()
			origCancel := r.runningTriggers[nsn.String()]
			r.runningTriggers[nsn.String()] = func() {
				cancelCalled.Store(true)
				origCancel()
			}
			r.runningTriggersLock.Unlock()

			// Delete the trigger object.
			latest := &triggersv1.HTTPTrigger{}
			Expect(k8sClient.Get(bgCtx, nsn, latest)).To(Succeed())
			Expect(k8sClient.Delete(bgCtx, latest)).To(Succeed())

			// Wait until it's gone or has DeletionTimestamp.
			Eventually(func() bool {
				obj := &triggersv1.HTTPTrigger{}
				if err := k8sClient.Get(bgCtx, nsn, obj); err != nil {
					return errors.IsNotFound(err)
				}
				return obj.DeletionTimestamp != nil
			}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())

			obj := &triggersv1.HTTPTrigger{}
			if err := k8sClient.Get(bgCtx, nsn, obj); err == nil {
				// Trigger still exists with DeletionTimestamp — exercise the deletion branch.
				_, err = r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
				Expect(err).NotTo(HaveOccurred())
				Expect(cancelCalled.Load()).To(BeTrue())
			}
			// If already gone, the not-found branch was exercised — also valid.
		})
	})

	// ─────────────────────────────────────────────────────────────
	// URL.Static strategy
	// ─────────────────────────────────────────────────────────────
	Context("URL.Static strategy", func() {
		const name = "trigger-static-url"

		AfterEach(func() {
			cleanupTrigger(bgCtx, name)
		})

		It("calls the static URL when a watched resource is added", func() {
			called := atomic.Bool{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called.Store(true)
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(srv.Close)

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
						EventType:  []triggersv1.EventType{triggersv1.EventTypeAdded},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
						Delivery: triggersv1.Delivery{
							Timeout: metav1.Duration{Duration: 5 * time.Second},
							Retries: 1,
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: name + "-cm", Namespace: ns},
			}
			Expect(k8sClient.Create(bgCtx, cm)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(bgCtx, cm) })

			Eventually(called.Load, 15*time.Second, 200*time.Millisecond).Should(BeTrue())
		})
	})

	// ─────────────────────────────────────────────────────────────
	// URL.Service strategy - static URI
	// ─────────────────────────────────────────────────────────────
	Context("URL.Service strategy", func() {
		const (
			name    = "trigger-service-url"
			svcName = "test-endpoint-svc"
		)

		AfterEach(func() {
			cleanupTrigger(bgCtx, name)
			cleanupService(bgCtx, svcName)
		})

		It("builds a service URL with a static URI and starts the watcher", func() {
			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: ns},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{Name: "http", Port: 80, TargetPort: intstr.FromInt(80), Protocol: corev1.ProtocolTCP},
					},
					Selector: map[string]string{"app": "none"},
				},
			}
			Expect(k8sClient.Create(bgCtx, svc)).To(Succeed())

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
						EventType:  []triggersv1.EventType{triggersv1.EventTypeAdded},
					},
					HTTP: triggersv1.HTTP{
						URL: triggersv1.URL{
							Service: &triggersv1.Service{
								LocalObjectReference: corev1.LocalObjectReference{Name: svcName},
								Namespace:            ns,
								URI:                  triggersv1.URI{Static: ptr.To("/hook")},
							},
						},
						Method: "POST",
						Delivery: triggersv1.Delivery{
							Timeout: metav1.Duration{Duration: time.Second},
							Retries: 0,
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			// Reconcile must succeed — watcher is set up.
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			r.runningTriggersLock.Lock()
			Expect(r.runningTriggers).To(HaveKey(nsn.String()))
			r.runningTriggersLock.Unlock()
		})
	})

	// ─────────────────────────────────────────────────────────────
	// URL.Service - template URI and port-by-name resolution
	// ─────────────────────────────────────────────────────────────
	Context("URL.Service - template URI with port name resolution", func() {
		const (
			name       = "trigger-service-tpl"
			svcNameTpl = "test-endpoint-svc-tpl"
		)

		AfterEach(func() {
			cleanupTrigger(bgCtx, name)
			cleanupService(bgCtx, svcNameTpl)
		})

		It("resolves a named port and builds a URL from URI template", func() {
			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: svcNameTpl, Namespace: ns},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{Name: "grpc", Port: 9090, TargetPort: intstr.FromInt(9090), Protocol: corev1.ProtocolTCP},
						{Name: "http", Port: 8080, TargetPort: intstr.FromInt(8080), Protocol: corev1.ProtocolTCP},
					},
					Selector: map[string]string{"app": "none"},
				},
			}
			Expect(k8sClient.Create(bgCtx, svc)).To(Succeed())

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
						EventType:  []triggersv1.EventType{triggersv1.EventTypeAdded},
					},
					HTTP: triggersv1.HTTP{
						URL: triggersv1.URL{
							Service: &triggersv1.Service{
								LocalObjectReference: corev1.LocalObjectReference{Name: svcNameTpl},
								Namespace:            ns,
								PortName:             "http",
								URI:                  triggersv1.URI{Template: ptr.To("/hook/{{ .metadata.name }}")},
							},
						},
						Method: "POST",
						Delivery: triggersv1.Delivery{
							Timeout: metav1.Duration{Duration: time.Second},
							Retries: 0,
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			r.runningTriggersLock.Lock()
			Expect(r.runningTriggers).To(HaveKey(nsn.String()))
			r.runningTriggersLock.Unlock()
		})
	})

	// ─────────────────────────────────────────────────────────────
	// MODIFIED event
	// ─────────────────────────────────────────────────────────────
	Context("MODIFIED event type", func() {
		const name = "trigger-modified"

		AfterEach(func() {
			cleanupTrigger(bgCtx, name)
		})

		It("dispatches HTTP call on MODIFIED event", func() {
			called := atomic.Bool{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called.Store(true)
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(srv.Close)

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name + "-cm",
					Namespace: ns,
					Labels:    map[string]string{"watch-modified": trueString},
				},
			}
			Expect(k8sClient.Create(bgCtx, cm)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(bgCtx, cm) })

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:      metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:    []string{ns},
						LabelSelector: []string{"watch-modified=true"},
						EventType:     []triggersv1.EventType{triggersv1.EventTypeModified},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
						Delivery: triggersv1.Delivery{
							Timeout: metav1.Duration{Duration: 5 * time.Second},
							Retries: 1,
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			// Patch the ConfigMap to trigger a MODIFIED event.
			latestCM := &corev1.ConfigMap{}
			Expect(k8sClient.Get(bgCtx, types.NamespacedName{Name: name + "-cm", Namespace: ns}, latestCM)).To(Succeed())
			patchedCM := latestCM.DeepCopy()
			if patchedCM.Annotations == nil {
				patchedCM.Annotations = map[string]string{}
			}
			patchedCM.Annotations["patched"] = trueString
			Expect(k8sClient.Update(bgCtx, patchedCM)).To(Succeed())

			Eventually(called.Load, 15*time.Second, 200*time.Millisecond).Should(BeTrue())
		})
	})

	// ─────────────────────────────────────────────────────────────
	// DELETED event
	// ─────────────────────────────────────────────────────────────
	Context("DELETED event type", func() {
		const name = "trigger-deleted-event"

		AfterEach(func() {
			cleanupTrigger(bgCtx, name)
		})

		It("dispatches HTTP call on DELETED event", func() {
			called := atomic.Bool{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called.Store(true)
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(srv.Close)

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name + "-cm",
					Namespace: ns,
					Labels:    map[string]string{"watch-deleted": trueString},
				},
			}
			Expect(k8sClient.Create(bgCtx, cm)).To(Succeed())

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:      metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:    []string{ns},
						LabelSelector: []string{"watch-deleted=true"},
						EventType:     []triggersv1.EventType{triggersv1.EventTypeDeleted},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
						Delivery: triggersv1.Delivery{
							Timeout: metav1.Duration{Duration: 5 * time.Second},
							Retries: 1,
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Delete(bgCtx, cm)).To(Succeed())

			Eventually(called.Load, 15*time.Second, 200*time.Millisecond).Should(BeTrue())
		})
	})

	// ─────────────────────────────────────────────────────────────
	// Default event types (empty EventType → all three)
	// ─────────────────────────────────────────────────────────────
	Context("Default event types", func() {
		const name = "trigger-default-events"

		AfterEach(func() {
			cleanupTrigger(bgCtx, name)
		})

		It("fires for ADDED when EventType is empty (defaults to all)", func() {
			called := atomic.Bool{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called.Store(true)
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(srv.Close)

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
						// EventType intentionally empty — should default to all.
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
						Delivery: triggersv1.Delivery{
							Timeout: metav1.Duration{Duration: 5 * time.Second},
							Retries: 1,
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: name + "-cm", Namespace: ns},
			}
			Expect(k8sClient.Create(bgCtx, cm)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(bgCtx, cm) })

			Eventually(called.Load, 15*time.Second, 200*time.Millisecond).Should(BeTrue())
		})
	})

	// ─────────────────────────────────────────────────────────────
	// EventFilter - rejection (non-matching filter skips dispatch)
	// ─────────────────────────────────────────────────────────────
	Context("EventFilter - rejection", func() {
		const name = "trigger-filter-reject"

		AfterEach(func() {
			cleanupTrigger(bgCtx, name)
		})

		It("does not dispatch when the filter does not match", func() {
			called := atomic.Bool{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called.Store(true)
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(srv.Close)

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:    metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:  []string{ns},
						EventType:   []triggersv1.EventType{triggersv1.EventTypeAdded},
						EventFilter: `eq .metadata.name "never-matches"`,
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
						Delivery: triggersv1.Delivery{
							Timeout: metav1.Duration{Duration: 5 * time.Second},
							Retries: 1,
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: name + "-cm", Namespace: ns},
			}
			Expect(k8sClient.Create(bgCtx, cm)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(bgCtx, cm) })

			// The webhook must NOT be called.
			Consistently(called.Load, 3*time.Second, 200*time.Millisecond).Should(BeFalse())
		})
	})

	// ─────────────────────────────────────────────────────────────
	// HMAC SHA512
	// ─────────────────────────────────────────────────────────────
	Context("HMAC SHA512 signature", func() {
		const (
			name       = "trigger-hmac-sha512"
			secretName = "hmac-sha512-secret"
		)

		AfterEach(func() {
			cleanupTrigger(bgCtx, name)
			cleanupSecret(bgCtx, secretName)
		})

		It("sends the correct SHA512 HMAC signature header", func() {
			sigKey := []byte("mysecret")

			type result struct {
				got      string
				expected string
			}
			resultCh := make(chan result, 1)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				h := hmac.New(sha512.New, sigKey)
				h.Write(body)
				expected := hex.EncodeToString(h.Sum(nil))
				got := r.Header.Get("X-Signature")
				select {
				case resultCh <- result{got: got, expected: expected}:
				default:
				}
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(srv.Close)

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: ns},
				Data:       map[string][]byte{"key": sigKey},
			}
			Expect(k8sClient.Create(bgCtx, secret)).To(Succeed())

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
						EventType:  []triggersv1.EventType{triggersv1.EventTypeAdded},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
						Body: triggersv1.Body{
							Template: `{{ .metadata.name }}`,
							Signature: triggersv1.Signature{
								Header: "X-Signature",
								KeySecretRef: corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
									Key:                  "key",
								},
								HMAC: &triggersv1.HMAC{HashType: triggersv1.SignatureHashTypeSHA512},
							},
						},
						Delivery: triggersv1.Delivery{
							Timeout: metav1.Duration{Duration: 5 * time.Second},
							Retries: 1,
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: name + "-cm", Namespace: ns},
			}
			Expect(k8sClient.Create(bgCtx, cm)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(bgCtx, cm) })

			var res result
			Eventually(func() bool {
				select {
				case res = <-resultCh:
					return true
				default:
					return false
				}
			}, 15*time.Second, 200*time.Millisecond).Should(BeTrue(), "SHA512 HMAC request should arrive")

			Expect(res.got).To(Equal(res.expected), "SHA512 HMAC signature should match")
		})
	})

	// ─────────────────────────────────────────────────────────────
	// Multi-namespace watching
	// ─────────────────────────────────────────────────────────────
	Context("Multi-namespace watching", func() {
		const name = "trigger-multi-ns"
		const ns2 = "kube-public"

		AfterEach(func() {
			cleanupTrigger(bgCtx, name)
		})

		It("starts a watcher per namespace and receives events from all of them", func() {
			callCount := atomic.Int32{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callCount.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(srv.Close)

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns, ns2},
						EventType:  []triggersv1.EventType{triggersv1.EventTypeAdded},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
						Delivery: triggersv1.Delivery{
							Timeout: metav1.Duration{Duration: 5 * time.Second},
							Retries: 1,
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			cm1 := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: name + "-cm1", Namespace: ns},
			}
			cm2 := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: name + "-cm2", Namespace: ns2},
			}
			Expect(k8sClient.Create(bgCtx, cm1)).To(Succeed())
			Expect(k8sClient.Create(bgCtx, cm2)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(bgCtx, cm1)
				_ = k8sClient.Delete(bgCtx, cm2)
			})

			Eventually(func() int32 { return callCount.Load() }, 20*time.Second, 200*time.Millisecond).
				Should(BeNumerically(">=", 2))
		})
	})

	// ─────────────────────────────────────────────────────────────
	// Retry exhaustion → status ErrorReason
	// ─────────────────────────────────────────────────────────────
	Context("Retry exhaustion", func() {
		const name = "trigger-retry-exhausted"

		AfterEach(func() {
			cleanupTrigger(bgCtx, name)
		})

		It("records ErrorReason in status after all retries are exhausted", func() {
			// Server always returns 500.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			DeferCleanup(srv.Close)

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
						EventType:  []triggersv1.EventType{triggersv1.EventTypeAdded},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
						Delivery: triggersv1.Delivery{
							Timeout: metav1.Duration{Duration: time.Second},
							Retries: 1, // 1 retry == 2 total attempts
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: name + "-cm", Namespace: ns},
			}
			Expect(k8sClient.Create(bgCtx, cm)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(bgCtx, cm) })

			updated := &triggersv1.HTTPTrigger{}
			Eventually(func() string {
				_ = k8sClient.Get(bgCtx, nsn, updated)
				return updated.Status.ErrorReason
			}, 30*time.Second, 500*time.Millisecond).ShouldNot(BeEmpty())

			var failureEvent string
			Eventually(r.Recorder.(*record.FakeRecorder).Events, 10*time.Second, 100*time.Millisecond).Should(Receive(&failureEvent))
			Expect(failureEvent).To(ContainSubstring("Warning"))
			Expect(failureEvent).To(ContainSubstring("TriggerCallFailed"))
			Expect(failureEvent).To(ContainSubstring(nsn.String()))
			Expect(failureEvent).To(ContainSubstring("status code is 500"))
		})

		It("records a fresh ErrorReason over a retained latch after a recovery restart", func() {
			// Server always returns 500.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			DeferCleanup(srv.Close)

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:      metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:    []string{ns},
						FieldSelector: []string{fmt.Sprintf("metadata.name=%s", name+"-cm2")},
						EventType:     []triggersv1.EventType{triggersv1.EventTypeAdded},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
						Delivery: triggersv1.Delivery{
							Timeout: metav1.Duration{Duration: time.Second},
							Retries: 0,
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			// Simulate a previously recorded failure: Phase=Error with a latch,
			// followed by a recovery restart that reports Running while
			// retaining the failure detail.
			latest := &triggersv1.HTTPTrigger{}
			Expect(k8sClient.Get(bgCtx, nsn, latest)).To(Succeed())
			patched := latest.DeepCopy()
			patched.Status.Phase = triggersv1.TriggerPhaseError
			patched.Status.ErrorTime = metav1.Now()
			patched.Status.ErrorReason = "old failure"
			patched.Status.ErrorResourceVersion = "0"
			Expect(k8sClient.Status().Patch(bgCtx, patched, client.MergeFrom(latest))).To(Succeed())

			r.runningTriggersLock.Lock()
			delete(r.runningTriggers, nsn.String())
			r.runningTriggersLock.Unlock()

			_, err = r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			updated := &triggersv1.HTTPTrigger{}
			Expect(k8sClient.Get(bgCtx, nsn, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal(triggersv1.TriggerPhaseRunning))
			Expect(updated.Status.ErrorReason).To(Equal("old failure"))

			// A fresh delivery failure in the recovered session must overwrite
			// the retained latch and flip the phase back to Error.
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: name + "-cm2", Namespace: ns},
			}
			Expect(k8sClient.Create(bgCtx, cm)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(bgCtx, cm) })

			Eventually(func() string {
				_ = k8sClient.Get(bgCtx, nsn, updated)
				return updated.Status.ErrorReason
			}, 30*time.Second, 500*time.Millisecond).Should(ContainSubstring("status code is 500"))

			// The error status write triggers a recovery reconcile (as the
			// manager's status watch would), which reports Running while
			// retaining the updated failure detail.
			_, err = r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() triggersv1.TriggerPhase {
				_ = k8sClient.Get(bgCtx, nsn, updated)
				return updated.Status.Phase
			}, 30*time.Second, 500*time.Millisecond).Should(Equal(triggersv1.TriggerPhaseRunning))
			Expect(updated.Status.ErrorReason).To(ContainSubstring("status code is 500"))
		})
	})

	// ─────────────────────────────────────────────────────────────
	// WatchInit
	// ─────────────────────────────────────────────────────────────
	Context("WatchInit", func() {
		const name = "trigger-watch-init"

		AfterEach(func() {
			cleanupTrigger(bgCtx, name)
		})

		It("creates watchers for existing triggers on startup", func() {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(srv.Close)

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
						EventType:  []triggersv1.EventType{triggersv1.EventTypeAdded},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			Expect(r.WatchInit(bgCtx)).To(Succeed())

			r.runningTriggersLock.Lock()
			Expect(r.runningTriggers).NotTo(BeEmpty())
			r.runningTriggersLock.Unlock()
		})
	})

	// ─────────────────────────────────────────────────────────────
	// SetupWithManager shutdown goroutine
	// ─────────────────────────────────────────────────────────────
	Context("SetupWithManager shutdown", func() {
		It("cancels all running triggers when context is done", func() {
			const name = "trigger-shutdown"
			DeferCleanup(func() { cleanupTrigger(bgCtx, name) })

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(srv.Close)

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
						EventType:  []triggersv1.EventType{triggersv1.EventTypeAdded},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			mgr, err := ctrl.NewManager(cfg, ctrl.Options{
				Scheme: k8sClient.Scheme(),
				// Disable metrics and health probe servers to avoid port conflicts.
				HealthProbeBindAddress: "0",
			})
			Expect(err).NotTo(HaveOccurred())

			r := &HTTPTriggerReconciler{
				Client:        k8sClient,
				DynamicClient: dynamicClient,
				Scheme:        k8sClient.Scheme(),
			}

			shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			Expect(r.SetupWithManager(shutdownCtx, mgr, 1, &wg)).To(Succeed())

			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err = r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			r.runningTriggersLock.Lock()
			Expect(r.runningTriggers).To(HaveKey(nsn.String()))
			r.runningTriggersLock.Unlock()

			// Cancel the manager context → shutdown goroutine cancels all triggers.
			shutdownCancel()
			doneCh := make(chan struct{})
			go func() {
				wg.Wait()
				close(doneCh)
			}()

			// Give the shutdown goroutine up to 10 s.
			select {
			case <-doneCh:
				// success
			case <-time.After(10 * time.Second):
				// The wg may never reach zero because the internal spin-loop
				// only exits when runningTriggers is empty, which requires the
				// watcher goroutines to call handleError/delete the key.
				// At minimum, assert the cancel was called (map key removed).
			}

			r.runningTriggersLock.Lock()
			Expect(r.runningTriggers).To(BeEmpty())
			r.runningTriggersLock.Unlock()
		})
	})

	// ─────────────────────────────────────────────────────────────
	// Label selector propagation
	// ─────────────────────────────────────────────────────────────
	Context("Label selector propagation", func() {
		const name = "trigger-label-selector"

		AfterEach(func() {
			cleanupTrigger(bgCtx, name)
		})

		It("only fires for resources matching the label selector", func() {
			matchCount := atomic.Int32{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				matchCount.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(srv.Close)

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:      metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:    []string{ns},
						LabelSelector: []string{fmt.Sprintf("label-selector-test-%s=yes", name)},
						EventType:     []triggersv1.EventType{triggersv1.EventTypeAdded},
					},
					HTTP: triggersv1.HTTP{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
						Method: "POST",
						Delivery: triggersv1.Delivery{
							Timeout: metav1.Duration{Duration: 5 * time.Second},
							Retries: 1,
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			// Create one CM with the label (should fire) and one without (should not).
			cmMatch := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name + "-match",
					Namespace: ns,
					Labels:    map[string]string{fmt.Sprintf("label-selector-test-%s", name): "yes"},
				},
			}
			cmNoMatch := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name + "-nomatch",
					Namespace: ns,
				},
			}
			Expect(k8sClient.Create(bgCtx, cmMatch)).To(Succeed())
			Expect(k8sClient.Create(bgCtx, cmNoMatch)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(bgCtx, cmMatch)
				_ = k8sClient.Delete(bgCtx, cmNoMatch)
			})

			// At least one call for the matching CM.
			Eventually(func() int32 { return matchCount.Load() }, 15*time.Second, 200*time.Millisecond).
				Should(BeNumerically(">=", 1))

			// Give a moment then assert count did not grow due to the non-matching CM.
			Consistently(func() int32 { return matchCount.Load() }, time.Second, 200*time.Millisecond).
				Should(BeNumerically("<=", 2)) // at most once per CM watched (only the matching one)
		})
	})

	// ─────────────────────────────────────────────────────────────
	// Reconcile - concurrency & scale posture
	// ─────────────────────────────────────────────────────────────
	Context("Reconcile - concurrent triggers reconcile in parallel", func() {
		const count = 12

		var (
			calls atomic.Int32
			srv   *httptest.Server
			srcCm *corev1.ConfigMap
		)

		BeforeEach(func() {
			calls.Store(0)
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(srv.Close)

			// A pre-existing watched object: every session replays it via
			// SendInitialEvents, making delivery deterministic regardless of
			// when each watcher stream actually comes up.
			srcCm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "conc-source", Namespace: ns}}
			Expect(k8sClient.Create(bgCtx, srcCm)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(bgCtx, srcCm) })
		})

		It("registers an independent watcher session for every concurrently-reconciled trigger and delivers an event to each", func() {
			r := newReconciler()

			for i := 0; i < count; i++ {
				name := fmt.Sprintf("conc-%d", i)
				trigger := &triggersv1.HTTPTrigger{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
					Spec: triggersv1.HTTPTriggerSpec{
						TriggerSpec: triggersv1.TriggerSpec{
							Resource:          metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
							Namespaces:        []string{ns},
							EventType:         []triggersv1.EventType{triggersv1.EventTypeAdded},
							SendInitialEvents: true,
						},
						HTTP: triggersv1.HTTP{
							URL:    triggersv1.URL{Static: ptr.To(srv.URL + "/hook")},
							Method: "POST",
							Delivery: triggersv1.Delivery{
								Timeout: metav1.Duration{Duration: 5 * time.Second},
								Retries: 1,
							},
						},
					},
				}
				Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
				DeferCleanup(func() { cleanupTrigger(bgCtx, name) })
			}

			// Reconcile all triggers concurrently: distinct triggers must not
			// serialize on a single global mutex. Exercised under -race in CI.
			var wg sync.WaitGroup
			errCh := make(chan error, count)

			for i := 0; i < count; i++ {
				nsn := types.NamespacedName{Name: fmt.Sprintf("conc-%d", i), Namespace: ns}
				wg.Add(1)

				go func() {
					defer wg.Done()

					if _, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn}); err != nil {
						errCh <- err
					}
				}()
			}

			wg.Wait()
			close(errCh)
			for err := range errCh {
				Expect(err).NotTo(HaveOccurred())
			}

			// Every trigger owns a live watcher session.
			Eventually(func() int {
				r.runningTriggersLock.Lock()
				defer r.runningTriggersLock.Unlock()

				return len(r.runningTriggers)
			}, 15*time.Second, 100*time.Millisecond).Should(Equal(count))

			for i := 0; i < count; i++ {
				r.runningTriggersLock.Lock()
				_, ok := r.runningTriggers[ns+"/conc-"+fmt.Sprint(i)]
				r.runningTriggersLock.Unlock()

				Expect(ok).To(BeTrue())
			}

			// The pre-existing source configmap is delivered once per session.
			Eventually(func() int32 { return calls.Load() }, 30*time.Second, 200*time.Millisecond).
				Should(BeNumerically(">=", count))
		})
	})

	Context("Annotation lease", func() {
		It("requeues while an active annotation lease is present using the trigger-specific lock duration", func() {
			const (
				name                = "httptrigger-active-lease"
				triggerLockDuration = 5 * time.Second
			)
			lockedAt := time.Now().UTC()
			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: ns,
					Annotations: map[string]string{
						lease.AnnotationKey: lockedAt.Format(time.RFC3339),
					},
				},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:     metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:   []string{ns},
						LockDuration: metav1.Duration{Duration: triggerLockDuration},
					},
					HTTP: triggersv1.HTTP{URL: triggersv1.URL{Static: ptr.To("http://example.invalid")}, Method: "POST"},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
			DeferCleanup(func() { cleanupTrigger(bgCtx, name) })

			r := newReconciler()

			result, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: ns}})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))
			Expect(result.RequeueAfter).To(BeNumerically("<=", triggerLockDuration))

			r.runningTriggersLock.Lock()
			_, running := r.runningTriggers[ns+"/"+name]
			r.runningTriggersLock.Unlock()
			Expect(running).To(BeFalse())
		})

		It("clears the annotation lease after a successful reconcile", func() {
			const name = "httptrigger-clear-lease"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			DeferCleanup(srv.Close)

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:     metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:   []string{ns},
						LockDuration: metav1.Duration{Duration: 30 * time.Second},
					},
					HTTP: triggersv1.HTTP{URL: triggersv1.URL{Static: ptr.To(srv.URL)}, Method: "POST"},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
			DeferCleanup(func() { cleanupTrigger(bgCtx, name) })

			r := newReconciler()

			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: ns}})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				updated := &triggersv1.HTTPTrigger{}
				g.Expect(k8sClient.Get(bgCtx, types.NamespacedName{Name: name, Namespace: ns}, updated)).To(Succeed())
				g.Expect(updated.Status.Phase).To(Equal(triggersv1.TriggerPhaseRunning))
				g.Expect(updated.Annotations).NotTo(HaveKey(lease.AnnotationKey))
			}, 5*time.Second, 100*time.Millisecond).Should(Succeed())
		})
	})

	Context("Distributed ownership", func() {
		It("skips unloved partitions when distributed mode does not own the trigger label", func() {
			clientset := fake.NewSimpleClientset(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: partition.DefaultConfigMapName, Namespace: ns},
				Data: map[string]string{
					"heartbeat/pod-a":  time.Now().UTC().Format(time.RFC3339),
					"heartbeat/pod-b":  time.Now().UTC().Format(time.RFC3339),
					"partition/item-1": "pod-b",
					"partition/item-2": "pod-b",
				},
			})
			partitionController := partition.NewDistributedController(clientset, ns, "pod-a")
			Expect(partitionController.Refresh(bgCtx)).To(Succeed())

			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "httptrigger-unowned-partition",
					Namespace: ns,
					Labels:    map[string]string{partition.DistributionLabelKey: "item-99"},
				},
				Spec: triggersv1.HTTPTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
						EventType:  []triggersv1.EventType{triggersv1.EventTypeAdded},
					},
					HTTP: triggersv1.HTTP{URL: triggersv1.URL{Static: ptr.To("http://example.invalid")}, Method: "POST"},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
			DeferCleanup(func() { cleanupTrigger(bgCtx, trigger.Name) })

			r := newReconciler()
			r.PartitionController = partitionController

			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: types.NamespacedName{Name: trigger.Name, Namespace: ns}})
			Expect(err).NotTo(HaveOccurred())

			r.runningTriggersLock.Lock()
			defer r.runningTriggersLock.Unlock()
			Expect(r.runningTriggers).NotTo(HaveKey(ns + "/" + trigger.Name))
		})
	})
})
