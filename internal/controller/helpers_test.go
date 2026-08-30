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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
		// channels cannot be marshaled to JSON
		ch := make(chan int)
		result := toJson(ch)
		Expect(result).To(HavePrefix("Error marshaling to JSON:"))
	})
})
