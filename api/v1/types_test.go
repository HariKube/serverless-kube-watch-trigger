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

package v1_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
)

var _ = Describe("API v1 Types", func() {
	Describe("EventType constants", func() {
		It("has correct string values", func() {
			Expect(string(triggersv1.EventTypeAdded)).To(Equal("ADDED"))
			Expect(string(triggersv1.EventTypeModified)).To(Equal("MODIFIED"))
			Expect(string(triggersv1.EventTypeDeleted)).To(Equal("DELETED"))
		})
	})

	Describe("Method constants", func() {
		It("has correct string values", func() {
			Expect(string(triggersv1.MethodGet)).To(Equal("GET"))
			Expect(string(triggersv1.MethodPost)).To(Equal("POST"))
			Expect(string(triggersv1.MethodPut)).To(Equal("PUT"))
			Expect(string(triggersv1.MethodPatch)).To(Equal("PATCH"))
		})
	})

	Describe("SignatureHashType constants", func() {
		It("has correct string values", func() {
			Expect(string(triggersv1.SignatureHashTypeSHA256)).To(Equal("SHA256"))
			Expect(string(triggersv1.SignatureHashTypeSHA512)).To(Equal("SHA512"))
		})
	})

	Describe("GroupVersion", func() {
		It("has the correct group and version", func() {
			Expect(triggersv1.GroupVersion.Group).To(Equal("triggers.harikube.info"))
			Expect(triggersv1.GroupVersion.Version).To(Equal("v1"))
		})
	})

	Describe("AddToScheme", func() {
		It("registers HTTPTrigger, PiTrigger, and their list types with the scheme", func() {
			s := scheme.Scheme
			Expect(triggersv1.AddToScheme(s)).To(Succeed())

			httpGVK := schema.GroupVersionKind{Group: "triggers.harikube.info", Version: "v1", Kind: "HTTPTrigger"}
			httpObj, err := s.New(httpGVK)
			Expect(err).NotTo(HaveOccurred())
			Expect(httpObj).To(BeAssignableToTypeOf(&triggersv1.HTTPTrigger{}))

			httpGVKList := schema.GroupVersionKind{Group: "triggers.harikube.info", Version: "v1", Kind: "HTTPTriggerList"}
			httpObjList, err := s.New(httpGVKList)
			Expect(err).NotTo(HaveOccurred())
			Expect(httpObjList).To(BeAssignableToTypeOf(&triggersv1.HTTPTriggerList{}))

			piGVK := schema.GroupVersionKind{Group: "triggers.harikube.info", Version: "v1", Kind: "PiTrigger"}
			piObj, err := s.New(piGVK)
			Expect(err).NotTo(HaveOccurred())
			Expect(piObj).To(BeAssignableToTypeOf(&triggersv1.PiTrigger{}))

			piGVKList := schema.GroupVersionKind{Group: "triggers.harikube.info", Version: "v1", Kind: "PiTriggerList"}
			piObjList, err := s.New(piGVKList)
			Expect(err).NotTo(HaveOccurred())
			Expect(piObjList).To(BeAssignableToTypeOf(&triggersv1.PiTriggerList{}))
		})
	})

	Describe("HTTPTrigger DeepCopy", func() {
		It("produces an independent copy", func() {
			original := &triggersv1.HTTPTrigger{}
			original.Name = "original"
			original.Spec.EventType = []triggersv1.EventType{triggersv1.EventTypeAdded}

			copy := original.DeepCopy()
			Expect(copy.Name).To(Equal("original"))

			copy.Name = "copy"
			copy.Spec.EventType[0] = triggersv1.EventTypeDeleted

			Expect(original.Name).To(Equal("original"))
			Expect(original.Spec.EventType[0]).To(Equal(triggersv1.EventTypeAdded))
		})

		It("handles nil gracefully", func() {
			var trigger *triggersv1.HTTPTrigger
			Expect(trigger.DeepCopy()).To(BeNil())
		})
	})

	Describe("HTTPTriggerList DeepCopy", func() {
		It("produces an independent copy", func() {
			original := &triggersv1.HTTPTriggerList{Items: []triggersv1.HTTPTrigger{{}}}
			original.Items[0].Name = "item0"

			copy := original.DeepCopyObject()
			Expect(copy).NotTo(BeNil())

			list, ok := copy.(*triggersv1.HTTPTriggerList)
			Expect(ok).To(BeTrue())
			Expect(list.Items[0].Name).To(Equal("item0"))
		})
	})

	Describe("PiTrigger DeepCopy", func() {
		It("produces an independent copy", func() {
			backoffLimit := int32(3)
			original := &triggersv1.PiTrigger{}
			original.Name = "original-pi"
			original.Spec.Agent.Image = "ghcr.io/example/pi-runner:latest"
			original.Spec.Agent.ConfigSecretRef = corev1.LocalObjectReference{Name: "pi-agent-config"}
			original.Spec.Agent.PromptsConfigMapRef = corev1.LocalObjectReference{Name: "pi-agent-prompts"}
			original.Spec.Agent.SkillsConfigMapRef = corev1.LocalObjectReference{Name: "pi-agent-skills"}
			original.Spec.Agent.Env = []corev1.EnvVar{{Name: "PI_PROVIDER", Value: "openai"}}
			original.Spec.Agent.Extensions = []string{"npm:pi-graft"}
			original.Spec.Agent.NoExtensions = true
			original.Spec.Agent.BackoffLimit = &backoffLimit

			copy := original.DeepCopy()
			Expect(copy.Name).To(Equal("original-pi"))
			Expect(copy.Spec.Agent.BackoffLimit).NotTo(BeNil())

			copy.Name = "copy-pi"
			*copy.Spec.Agent.BackoffLimit = 5
			copy.Spec.Agent.Env[0].Value = "anthropic"
			copy.Spec.Agent.Extensions[0] = "npm:custom"

			Expect(original.Name).To(Equal("original-pi"))
			Expect(*original.Spec.Agent.BackoffLimit).To(Equal(int32(3)))
			Expect(original.Spec.Agent.Env[0].Value).To(Equal("openai"))
			Expect(original.Spec.Agent.Extensions[0]).To(Equal("npm:pi-graft"))
		})
	})

	Describe("PiTriggerList DeepCopy", func() {
		It("produces an independent copy", func() {
			original := &triggersv1.PiTriggerList{Items: []triggersv1.PiTrigger{{}}}
			original.Items[0].Name = "pi-item0"

			copy := original.DeepCopyObject()
			Expect(copy).NotTo(BeNil())

			list, ok := copy.(*triggersv1.PiTriggerList)
			Expect(ok).To(BeTrue())
			Expect(list.Items[0].Name).To(Equal("pi-item0"))
		})
	})

	Describe("TriggerSpec defaults", func() {
		It("zero-value has empty EventType slice", func() {
			ts := triggersv1.TriggerSpec{}
			Expect(ts.EventType).To(BeEmpty())
		})

		It("zero-value has false SendInitialEvents", func() {
			ts := triggersv1.TriggerSpec{}
			Expect(ts.SendInitialEvents).To(BeFalse())
		})

		It("deep-copies lock duration independently", func() {
			original := &triggersv1.TriggerSpec{LockDuration: metav1.Duration{Duration: 7 * time.Second}}

			copy := original.DeepCopy()
			copy.LockDuration.Duration = 11 * time.Second

			Expect(original.LockDuration.Duration).To(Equal(7 * time.Second))
			Expect(copy.LockDuration.Duration).To(Equal(11 * time.Second))
		})
	})
})
