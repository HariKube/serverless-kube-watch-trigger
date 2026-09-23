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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
		It("registers HTTPTrigger, AITrigger, and their list types with the scheme", func() {
			s := scheme.Scheme
			Expect(triggersv1.AddToScheme(s)).To(Succeed())

			httpGVK := schema.GroupVersionKind{
				Group:   "triggers.harikube.info",
				Version: "v1",
				Kind:    "HTTPTrigger",
			}
			httpObj, err := s.New(httpGVK)
			Expect(err).NotTo(HaveOccurred())
			Expect(httpObj).To(BeAssignableToTypeOf(&triggersv1.HTTPTrigger{}))

			httpGVKList := schema.GroupVersionKind{
				Group:   "triggers.harikube.info",
				Version: "v1",
				Kind:    "HTTPTriggerList",
			}
			httpObjList, err := s.New(httpGVKList)
			Expect(err).NotTo(HaveOccurred())
			Expect(httpObjList).To(BeAssignableToTypeOf(&triggersv1.HTTPTriggerList{}))

			aiGVK := schema.GroupVersionKind{
				Group:   "triggers.harikube.info",
				Version: "v1",
				Kind:    "AITrigger",
			}
			aiObj, err := s.New(aiGVK)
			Expect(err).NotTo(HaveOccurred())
			Expect(aiObj).To(BeAssignableToTypeOf(&triggersv1.AITrigger{}))

			aiGVKList := schema.GroupVersionKind{
				Group:   "triggers.harikube.info",
				Version: "v1",
				Kind:    "AITriggerList",
			}
			aiObjList, err := s.New(aiGVKList)
			Expect(err).NotTo(HaveOccurred())
			Expect(aiObjList).To(BeAssignableToTypeOf(&triggersv1.AITriggerList{}))
		})
	})

	Describe("HTTPTrigger DeepCopy", func() {
		It("produces an independent copy", func() {
			original := &triggersv1.HTTPTrigger{}
			original.Name = "original"
			original.Spec.EventType = []triggersv1.EventType{triggersv1.EventTypeAdded}

			copy := original.DeepCopy()
			Expect(copy.Name).To(Equal("original"))

			// Mutate copy — original should be unchanged
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
			original := &triggersv1.HTTPTriggerList{
				Items: []triggersv1.HTTPTrigger{
					{},
				},
			}
			original.Items[0].Name = "item0"

			copy := original.DeepCopyObject()
			Expect(copy).NotTo(BeNil())

			list, ok := copy.(*triggersv1.HTTPTriggerList)
			Expect(ok).To(BeTrue())
			Expect(list.Items[0].Name).To(Equal("item0"))
		})
	})

	Describe("AITrigger DeepCopy", func() {
		It("produces an independent copy", func() {
			temperature := "0.5"
			original := &triggersv1.AITrigger{}
			original.Name = "original-ai"
			original.Spec.Request.Model = "gpt-4o-mini"
			original.Spec.Request.PromptTemplate = "{{ .metadata.name }}"
			original.Spec.Request.Temperature = &temperature

			copy := original.DeepCopy()
			Expect(copy.Name).To(Equal("original-ai"))
			Expect(copy.Spec.Request.Temperature).NotTo(BeNil())

			copy.Name = "copy-ai"
			*copy.Spec.Request.Temperature = "0.8"

			Expect(original.Name).To(Equal("original-ai"))
			Expect(*original.Spec.Request.Temperature).To(Equal("0.5"))
		})
	})

	Describe("AITriggerList DeepCopy", func() {
		It("produces an independent copy", func() {
			original := &triggersv1.AITriggerList{
				Items: []triggersv1.AITrigger{{}},
			}
			original.Items[0].Name = "ai-item0"

			copy := original.DeepCopyObject()
			Expect(copy).NotTo(BeNil())

			list, ok := copy.(*triggersv1.AITriggerList)
			Expect(ok).To(BeTrue())
			Expect(list.Items[0].Name).To(Equal("ai-item0"))
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
	})
})
