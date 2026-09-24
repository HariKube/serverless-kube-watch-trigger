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
	"sync"
	"text/template"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
)

var _ = Describe("toJson helper", func() {
	It("marshals a simple string", func() {
		result := toJson("hello")
		Expect(result).To(Equal(`"hello"`))
	})

	It("marshals a map to JSON", func() {
		result := toJson(map[string]string{"key": "value"})
		Expect(result).To(Equal(`{"key":"value"}`))
	})

	It("marshals a slice to JSON", func() {
		result := toJson([]int{1, 2, 3})
		Expect(result).To(Equal(`[1,2,3]`))
	})

	It("marshals a nil value", func() {
		result := toJson(nil)
		Expect(result).To(Equal(`null`))
	})

	It("marshals an integer", func() {
		result := toJson(42)
		Expect(result).To(Equal(`42`))
	})

	It("marshals a boolean", func() {
		result := toJson(true)
		Expect(result).To(Equal(`true`))
	})

	It("marshals a nested struct", func() {
		type Inner struct {
			X int `json:"x"`
		}
		type Outer struct {
			Name  string `json:"name"`
			Inner Inner  `json:"inner"`
		}
		result := toJson(Outer{Name: "test", Inner: Inner{X: 7}})
		Expect(result).To(Equal(`{"name":"test","inner":{"x":7}}`))
	})

	It("returns an error string for un-marshalable types", func() {
		ch := make(chan int)
		result := toJson(ch)
		Expect(result).To(HavePrefix("Error marshaling to JSON:"))
	})
})

var _ = Describe("trigger helper utilities", func() {
	It("builds resource info for core and grouped API versions", func() {
		gvr, gvk := buildTriggerResourceInfo(metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"})
		Expect(gvr.Group).To(BeEmpty())
		Expect(gvr.Version).To(Equal("v1"))
		Expect(gvr.Resource).To(Equal("configmaps"))
		Expect(gvk.Group).To(BeEmpty())
		Expect(gvk.Version).To(Equal("v1"))
		Expect(gvk.Kind).To(Equal("ConfigMap"))

		gvr, gvk = buildTriggerResourceInfo(metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"})
		Expect(gvr.Group).To(Equal("apps"))
		Expect(gvr.Version).To(Equal("v1"))
		Expect(gvr.Resource).To(Equal("deployments"))
		Expect(gvk.Group).To(Equal("apps"))
		Expect(gvk.Version).To(Equal("v1"))
		Expect(gvk.Kind).To(Equal("Deployment"))
	})

	It("defaults empty event types to added modified and deleted", func() {
		eventTypes := buildTriggerEventTypes(nil)
		Expect(eventTypes).To(HaveKeyWithValue(string(triggersv1.EventTypeAdded), true))
		Expect(eventTypes).To(HaveKeyWithValue(string(triggersv1.EventTypeModified), true))
		Expect(eventTypes).To(HaveKeyWithValue(string(triggersv1.EventTypeDeleted), true))

		explicit := buildTriggerEventTypes([]triggersv1.EventType{triggersv1.EventTypeAdded})
		Expect(explicit).To(HaveLen(1))
		Expect(explicit).To(HaveKeyWithValue(string(triggersv1.EventTypeAdded), true))
	})

	It("renders URL strategies from shared compiled templates", func() {
		compiledTemplates := map[string]*template.Template{}
		Expect(addCompiledTemplate(compiledTemplates, urlTemplateName, "https://hooks.example/{{ .metadata.name }}", nil)).To(Succeed())
		Expect(addCompiledTemplate(compiledTemplates, uriTemplateName, "/events/{{ .metadata.name }}", nil)).To(Succeed())

		object := map[string]any{
			"metadata": map[string]any{"name": "demo"},
		}

		url, err := buildTriggerURL(
			triggersv1.URL{Static: ptr.To("https://static.example")},
			compiledTemplates,
			object,
			"",
			0,
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(url).To(Equal("https://static.example"))

		url, err = buildTriggerURL(
			triggersv1.URL{Template: ptr.To("https://hooks.example/{{ .metadata.name }}")},
			compiledTemplates,
			object,
			"",
			0,
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(url).To(Equal("https://hooks.example/demo"))

		url, err = buildTriggerURL(
			triggersv1.URL{Service: &triggersv1.Service{
				LocalObjectReference: corev1.LocalObjectReference{Name: "receiver"},
				Namespace:            "default",
				URI:                  triggersv1.URI{Template: ptr.To("/events/{{ .metadata.name }}")},
			}},
			compiledTemplates,
			object,
			"http",
			8080,
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(url).To(Equal("http://receiver.default:8080/events/demo"))
	})

	It("merges rendered template headers secret headers and static headers", func() {
		compiledTemplates := map[string]*template.Template{}
		Expect(addCompiledTemplate(compiledTemplates, "header_template_X-Resource", "{{ .metadata.name }}", nil)).To(Succeed())

		headers, err := buildTriggerHeaders(
			"application/json",
			triggersv1.Headers{
				Static: map[string]string{"X-Static": "static"},
				Template: map[string]string{
					"X-Resource": "{{ .metadata.name }}",
				},
				FromSecretRef: map[string]corev1.SecretKeySelector{
					"Authorization": {},
				},
			},
			map[string]string{"Authorization": "Bearer token"},
			compiledTemplates,
			map[string]any{"metadata": map[string]any{"name": "demo"}},
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(headers).To(Equal(map[string]string{
			"Content-Type":  "application/json",
			"X-Static":      "static",
			"X-Resource":    "demo",
			"Authorization": "Bearer token",
		}))
	})

	It("normalizes concurrency timeout and default method", func() {
		Expect(normalizeConcurrency(0)).To(Equal(uint8(1)))
		Expect(normalizeConcurrency(3)).To(Equal(uint8(3)))
		Expect(normalizeHTTPTimeout(0)).To(Equal(10 * time.Second))
		Expect(normalizeHTTPTimeout(2 * time.Second)).To(Equal(2 * time.Second))
		Expect(methodOrDefault("")).To(Equal("POST"))
		Expect(methodOrDefault(triggersv1.MethodPatch)).To(Equal("PATCH"))
	})

	Context("event emission helpers", func() {
		const ns = "default"

		It("records a failure event", func() {
			recorder := record.NewFakeRecorder(1)
			trigger := &triggersv1.HTTPTrigger{ObjectMeta: metav1.ObjectMeta{Name: "httptrigger-failure", Namespace: ns}}
			metadata := map[string]interface{}{"name": "source", "namespace": ns, "resourceVersion": "28"}

			emitTriggerCallFailureEvent(recorder, trigger, "default/httptrigger-failure", "POST", "https://example.test/hook", watch.Modified, metadata, errors.New("status code is 500"))

			var event string
			Eventually(recorder.Events, 5*time.Second, 100*time.Millisecond).Should(Receive(&event))
			Expect(event).To(ContainSubstring("Warning"))
			Expect(event).To(ContainSubstring("TriggerCallFailed"))
			Expect(event).To(ContainSubstring("default/httptrigger-failure"))
			Expect(event).To(ContainSubstring("status code is 500"))
		})

		It("records a detailed warning event after patching trigger status", func() {
			recorder := record.NewFakeRecorder(1)
			runningTriggersLock := sync.Mutex{}
			runningTriggers := map[string]func(){
				"default/httptrigger-event": func() {},
			}
			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: "httptrigger-event", Namespace: ns},
			}

			cancelCalled := false
			stopCalled := false
			runningTriggers["default/httptrigger-event"] = func() {
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
				"default/httptrigger-event",
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
			Expect(runningTriggers).NotTo(HaveKey("default/httptrigger-event"))

			var event string
			Eventually(recorder.Events, 5*time.Second, 100*time.Millisecond).Should(Receive(&event))
			Expect(event).To(ContainSubstring("Warning"))
			Expect(event).To(ContainSubstring("WatcherClosed"))
			Expect(event).To(ContainSubstring("default/httptrigger-event"))
			Expect(event).To(ContainSubstring("closed channel"))
			Expect(event).To(ContainSubstring("resourceVersion=42"))
		})

		It("does not patch status or tear down state for a superseded session", func() {
			recorder := record.NewFakeRecorder(1)
			runningTriggersLock := sync.Mutex{}
			runningTriggers := map[string]func(){}
			trigger := &triggersv1.HTTPTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: "httptrigger-event", Namespace: ns},
			}

			cancelCalled := false
			stopCalled := false
			patchCalled := false
			runningTriggers["default/httptrigger-event"] = func() {
				cancelCalled = true
			}

			// sessionStale already closed -> the session was cancelled and
			// possibly replaced (trigger update, deletion or shutdown).
			sessionStale := make(chan struct{})
			close(sessionStale)

			handleTriggerWatcherError(
				context.Background(),
				errors.New("closed channel"),
				logr.Discard(),
				recorder,
				trigger,
				"default/httptrigger-event",
				"42",
				&runningTriggersLock,
				runningTriggers,
				sessionStale,
				func() {
					stopCalled = true
				},
				func(_ context.Context, _ metav1.Time, _, _ string) (bool, error) {
					patchCalled = true

					return true, nil
				},
			)

			Expect(patchCalled).To(BeFalse())
			Expect(cancelCalled).To(BeFalse())
			Expect(stopCalled).To(BeFalse())
			Expect(runningTriggers).To(HaveKey("default/httptrigger-event"))

			Consistently(recorder.Events, 250*time.Millisecond).ShouldNot(Receive())
		})
	})
})
