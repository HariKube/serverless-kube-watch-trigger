package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
)

type observedAIRequest struct {
	Method  string
	Headers http.Header
	Body    aiControllerPayload
}

type aiControllerPayload struct {
	Model       string                    `json:"model"`
	Messages    []aiControllerPayloadItem `json:"messages"`
	Temperature *float64                  `json:"temperature,omitempty"`
	MaxTokens   *int32                    `json:"max_tokens,omitempty"`
}

type aiControllerPayloadItem struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func newAIReconciler() *AITriggerReconciler {
	r := &AITriggerReconciler{
		Client:              k8sClient,
		DynamicClient:       dynamicClient,
		Scheme:              k8sClient.Scheme(),
		Recorder:            record.NewFakeRecorder(10),
		ctx:                 ctx,
		runningTriggersLock: sync.Mutex{},
		runningTriggers:     map[string]func(){},
		triggerLocksLock:    sync.Mutex{},
		triggerLocks:        map[string]*sync.Mutex{},
	}
	DeferCleanup(func() {
		r.runningTriggersLock.Lock()
		for _, c := range r.runningTriggers {
			c()
		}
		r.runningTriggers = map[string]func(){}
		r.runningTriggersLock.Unlock()
	})
	return r
}

func cleanupAITrigger(ctx context.Context, name string) {
	trigger := &triggersv1.AITrigger{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, trigger); err == nil {
		_ = k8sClient.Delete(ctx, trigger)
	}
}

func cleanupConfigMap(ctx context.Context, name string) {
	configMap := &corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, configMap); err == nil {
		_ = k8sClient.Delete(ctx, configMap)
	}
}

var _ = Describe("AITrigger Controller", func() {
	const ns = "default"
	bgCtx := context.Background()

	Context("Reconcile - trigger not found", func() {
		It("returns no error when the resource does not exist", func() {
			r := newAIReconciler()
			_, err := r.Reconcile(bgCtx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "does-not-exist-ai", Namespace: ns},
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("Reconcile - invalid trigger content", func() {
		const name = "aitrigger-invalid"

		AfterEach(func() {
			cleanupAITrigger(bgCtx, name)
		})

		It("records ErrorReason in status for a bad prompt template", func() {
			trigger := &triggersv1.AITrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.AITriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
					},
					AIModel: triggersv1.AIModel{
						URL: triggersv1.URL{Static: ptr.To("http://example.invalid/v1/chat/completions")},
						Request: triggersv1.AIRequest{
							Model:          "gpt-4o-mini",
							PromptTemplate: "{{invalid template",
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newAIReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			updated := &triggersv1.AITrigger{}
			Eventually(func() string {
				_ = k8sClient.Get(bgCtx, nsn, updated)
				return updated.Status.ErrorReason
			}, 5*time.Second, 200*time.Millisecond).ShouldNot(BeEmpty())
		})
	})

	Context("watcher error handling", func() {
		It("records a detailed warning event after patching trigger status", func() {
			recorder := record.NewFakeRecorder(1)
			runningTriggersLock := sync.Mutex{}
			runningTriggers := map[string]func(){
				"default/aitrigger-event": func() {},
			}
			trigger := &triggersv1.AITrigger{
				ObjectMeta: metav1.ObjectMeta{Name: "aitrigger-event", Namespace: ns},
			}

			cancelCalled := false
			stopCalled := false
			runningTriggers["default/aitrigger-event"] = func() {
				cancelCalled = true
			}

			var (
				patchesMu                   sync.Mutex
				patchedErrorTime            metav1.Time
				patchedErrorReason          string
				patchedErrorResourceVersion string
			)

			handleTriggerWatcherError(
				context.Background(),
				errors.New("closed channel"),
				logr.Discard(),
				recorder,
				trigger,
				"default/aitrigger-event",
				"42",
				&runningTriggersLock,
				runningTriggers,
				context.Background().Done(),
				func() {
					stopCalled = true
				},
				func(_ context.Context, errorTime metav1.Time, errorReason, errorResourceVersion string) (bool, error) {
					patchesMu.Lock()
					defer patchesMu.Unlock()
					patchedErrorTime = errorTime
					patchedErrorReason = errorReason
					patchedErrorResourceVersion = errorResourceVersion

					return true, nil
				},
			)

			Eventually(func() string {
				patchesMu.Lock()
				defer patchesMu.Unlock()

				return patchedErrorReason
			}, 5*time.Second, 100*time.Millisecond).Should(Equal("closed channel"))
			patchesMu.Lock()
			defer patchesMu.Unlock()
			Expect(patchedErrorTime.IsZero()).To(BeFalse())
			Expect(patchedErrorResourceVersion).To(Equal("42"))
			Expect(cancelCalled).To(BeTrue())
			Expect(stopCalled).To(BeTrue())
			Expect(runningTriggers).NotTo(HaveKey("default/aitrigger-event"))

			var event string
			Eventually(recorder.Events, 5*time.Second, 100*time.Millisecond).Should(Receive(&event))
			Expect(event).To(ContainSubstring("Warning"))
			Expect(event).To(ContainSubstring("WatcherClosed"))
			Expect(event).To(ContainSubstring("default/aitrigger-event"))
			Expect(event).To(ContainSubstring("closed channel"))
			Expect(event).To(ContainSubstring("resourceVersion=42"))
		})

		It("does not patch status when the controller context is cancelled (shutdown)", func() {
			runningTriggersLock := sync.Mutex{}
			runningTriggers := map[string]func(){}
			trigger := &triggersv1.AITrigger{
				ObjectMeta: metav1.ObjectMeta{Name: "aitrigger-shutdown", Namespace: ns},
			}

			cancelCalled := false
			runningTriggers["default/aitrigger-shutdown"] = func() {
				cancelCalled = true
			}

			patchCalls := &atomic.Int32{}

			shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
			shutdownCancel()

			handleTriggerWatcherError(
				shutdownCtx,
				errors.New("shutting down"),
				logr.Discard(),
				record.NewFakeRecorder(1),
				trigger,
				"default/aitrigger-shutdown",
				"0",
				&runningTriggersLock,
				runningTriggers,
				context.Background().Done(),
				func() {},
				func(_ context.Context, _ metav1.Time, _, _ string) (bool, error) {
					patchCalls.Add(1)

					return true, nil
				},
			)

			Expect(cancelCalled).To(BeTrue())
			Expect(runningTriggers).NotTo(HaveKey("default/aitrigger-shutdown"))

			// Any worker spawned by the handler must bail out before touching
			// the API; it must never retry against a cancelled context.
			Consistently(func() int32 { return patchCalls.Load() }, 2*time.Second, 100*time.Millisecond).Should(BeZero())
		})
	})

	Context("Reconcile - successful AI model invocation", func() {
		const (
			triggerName   = "aitrigger-success"
			configMapName = "aitrigger-configmap"
			secretName    = "aitrigger-secret"
		)

		var (
			received chan observedAIRequest
			srv      *httptest.Server
		)

		BeforeEach(func() {
			received = make(chan observedAIRequest, 1)
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer GinkgoRecover()

				bodyBytes, err := io.ReadAll(r.Body)
				Expect(err).NotTo(HaveOccurred())

				payload := aiControllerPayload{}
				Expect(json.Unmarshal(bodyBytes, &payload)).To(Succeed())

				received <- observedAIRequest{
					Method:  r.Method,
					Headers: r.Header.Clone(),
					Body:    payload,
				}

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"id":"chatcmpl-test"}`))
			}))

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: ns},
				Data: map[string][]byte{
					"authorization": []byte("Bearer test-token"),
				},
			}
			Expect(k8sClient.Create(bgCtx, secret)).To(Succeed())

			temperature := "0.42"
			maxTokens := int32(64)
			trigger := &triggersv1.AITrigger{
				ObjectMeta: metav1.ObjectMeta{Name: triggerName, Namespace: ns},
				Spec: triggersv1.AITriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:      metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:    []string{ns},
						FieldSelector: []string{fmt.Sprintf("metadata.name=%s", configMapName)},
						EventType:     []triggersv1.EventType{triggersv1.EventTypeAdded},
						Concurrency:   1,
					},
					AIModel: triggersv1.AIModel{
						URL:    triggersv1.URL{Static: ptr.To(srv.URL)},
						Method: triggersv1.MethodPost,
						Headers: triggersv1.Headers{
							Static: map[string]string{
								"X-Trigger": "aitrigger",
							},
							FromSecretRef: map[string]corev1.SecretKeySelector{
								"Authorization": {
									LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
									Key:                  "authorization",
								},
							},
						},
						Request: triggersv1.AIRequest{
							Model:          "gpt-4o-mini",
							SystemPrompt:   "Summarize changes in {{ .metadata.namespace }}",
							PromptTemplate: "Resource {{ .metadata.name }} carries {{ toJson .data }}",
							Temperature:    &temperature,
							MaxTokens:      &maxTokens,
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
		})

		AfterEach(func() {
			srv.Close()
			cleanupConfigMap(bgCtx, configMapName)
			cleanupAITrigger(bgCtx, triggerName)
			cleanupSecret(bgCtx, secretName)
		})

		It("renders an OpenAI-compatible payload and sends it to the configured endpoint", func() {
			r := newAIReconciler()
			nsn := types.NamespacedName{Name: triggerName, Namespace: ns}

			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() bool {
				r.runningTriggersLock.Lock()
				defer r.runningTriggersLock.Unlock()
				_, ok := r.runningTriggers[nsn.String()]
				return ok
			}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())

			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: configMapName, Namespace: ns},
				Data: map[string]string{
					"key": "value",
				},
			}
			Expect(k8sClient.Create(bgCtx, configMap)).To(Succeed())

			var request observedAIRequest
			Eventually(received, 10*time.Second, 100*time.Millisecond).Should(Receive(&request))
			Expect(request.Method).To(Equal(http.MethodPost))
			Expect(request.Body.Model).To(Equal("gpt-4o-mini"))
			Expect(request.Body.Messages).To(HaveLen(2))

			Expect(request.Headers.Get("Content-Type")).To(Equal("application/json"))
			Expect(request.Headers.Get("Authorization")).To(Equal("Bearer test-token"))
			Expect(request.Headers.Get("X-Trigger")).To(Equal("aitrigger"))
			Expect(request.Body.Temperature).NotTo(BeNil())
			Expect(*request.Body.Temperature).To(BeNumerically("==", 0.42))
			Expect(request.Body.MaxTokens).NotTo(BeNil())
			Expect(*request.Body.MaxTokens).To(Equal(int32(64)))
			Expect(request.Body.Messages[0]).To(Equal(aiControllerPayloadItem{Role: "system", Content: "Summarize changes in default"}))
			Expect(request.Body.Messages[1].Role).To(Equal("user"))
			Expect(request.Body.Messages[1].Content).To(ContainSubstring("Resource aitrigger-configmap carries"))
			Expect(request.Body.Messages[1].Content).To(ContainSubstring(`"key":"value"`))

			updated := &triggersv1.AITrigger{}
			Eventually(func() string {
				_ = k8sClient.Get(bgCtx, nsn, updated)
				return updated.Status.ErrorReason
			}, 5*time.Second, 100*time.Millisecond).Should(BeEmpty())
			Eventually(func() string {
				_ = k8sClient.Get(bgCtx, nsn, updated)
				return updated.Status.ErrorResourceVersion
			}, 5*time.Second, 100*time.Millisecond).ShouldNot(BeEmpty())
		})
	})

	Context("Reconcile - reports Running after watcher recovery restart", func() {
		const name = "aitrigger-recovery"
		var srv *httptest.Server

		BeforeEach(func() {
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			trigger := &triggersv1.AITrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.AITriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
					},
					AIModel: triggersv1.AIModel{
						URL: triggersv1.URL{Static: ptr.To(srv.URL)},
						Request: triggersv1.AIRequest{
							Model:          "gpt-4o-mini",
							PromptTemplate: "{{ .metadata.name }}",
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
		})

		AfterEach(func() {
			srv.Close()
			cleanupAITrigger(bgCtx, name)
		})

		It("re-establishes the watcher, reports Running and keeps the error detail", func() {
			r := newAIReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}

			// First reconcile - starts the watcher and reports Running.
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			// Simulate the error status patch made by handleTriggerWatcherError.
			latest := &triggersv1.AITrigger{}
			Expect(k8sClient.Get(bgCtx, nsn, latest)).To(Succeed())
			patched := latest.DeepCopy()
			patched.Status.Phase = triggersv1.TriggerPhaseError
			patched.Status.ErrorTime = metav1.Now()
			patched.Status.ErrorReason = "status code is 500"
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

			updated := &triggersv1.AITrigger{}
			Expect(k8sClient.Get(bgCtx, nsn, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal(triggersv1.TriggerPhaseRunning))
			Expect(updated.Status.ErrorReason).To(Equal("status code is 500"))
			Expect(updated.Status.ErrorTime.IsZero()).To(BeFalse())
			Expect(updated.Status.ErrorResourceVersion).To(Equal("42"))
		})
	})

	Context("WatchInit", func() {
		const name = "aitrigger-watchinit"

		AfterEach(func() {
			cleanupAITrigger(bgCtx, name)
		})

		It("starts watchers for existing AITrigger resources", func() {
			trigger := &triggersv1.AITrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.AITriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:    metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:  []string{ns},
						Concurrency: 1,
					},
					AIModel: triggersv1.AIModel{
						URL: triggersv1.URL{Static: ptr.To("http://example.invalid/v1/chat/completions")},
						Request: triggersv1.AIRequest{
							Model:          "gpt-4o-mini",
							PromptTemplate: "{{ .metadata.name }}",
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newAIReconciler()
			Expect(r.WatchInit(bgCtx)).To(Succeed())
			Eventually(func() bool {
				r.runningTriggersLock.Lock()
				defer r.runningTriggersLock.Unlock()
				_, ok := r.runningTriggers[ns+"/"+name]
				return ok
			}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
		})
	})

	Context("Reconcile - removes the watcher session when a trigger is deleted", func() {
		const name = "aitrigger-cleanup"
		var cancelCalled atomic.Bool

		BeforeEach(func() {
			cancelCalled.Store(false)
			trigger := &triggersv1.AITrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.AITriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:    metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:  []string{ns},
						Concurrency: 1,
					},
					AIModel: triggersv1.AIModel{
						URL: triggersv1.URL{Static: ptr.To("http://example.invalid/v1/chat/completions")},
						Request: triggersv1.AIRequest{
							Model:          "gpt-4o-mini",
							PromptTemplate: "{{ .metadata.name }}",
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
		})

		AfterEach(func() {
			cleanupAITrigger(bgCtx, name)
		})

		It("cancels and drops the running watcher when the trigger is gone (NotFound)", func() {
			r := newAIReconciler()
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
			Expect(k8sClient.Delete(bgCtx, &triggersv1.AITrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			})).To(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(bgCtx, nsn, &triggersv1.AITrigger{})
				return apierrors.IsNotFound(err)
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
})
