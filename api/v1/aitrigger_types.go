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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AIRequest defines the OpenAI-compatible request rendered for each matching event.
type AIRequest struct {
	// +kubebuilder:validation:Required
	// Model represents the model name sent to the AI provider.
	Model string `json:"model"`

	// +kubebuilder:validation:Optional
	// SystemPrompt represents an optional system prompt template.
	SystemPrompt string `json:"systemPrompt,omitempty"`

	// +kubebuilder:validation:Required
	// PromptTemplate represents the user prompt template rendered from the watched object.
	PromptTemplate string `json:"promptTemplate"`

	// +kubebuilder:validation:Optional
	// Temperature represents the sampling temperature sent to the AI provider as a decimal string.
	Temperature *string `json:"temperature,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// MaxTokens represents the maximum number of completion tokens.
	MaxTokens *int32 `json:"maxTokens,omitempty"`
}

// AIModel represents an OpenAI-compatible model invocation target.
type AIModel struct {
	// +kubebuilder:validation:Required
	// URL represents the URL generator strategy.
	URL URL `json:"url"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=POST
	// Method represents the HTTP method used to call the AI provider.
	Method Method `json:"method,omitempty"`

	// +kubebuilder:validation:Optional
	// Auth represents different authentication methods.
	Auth Auth `json:"auth,omitempty"`

	// +kubebuilder:validation:Optional
	// Headers represents extra headers of the request.
	Headers Headers `json:"headers,omitempty"`

	// +kubebuilder:validation:Optional
	// Delivery represents the delivery details.
	Delivery Delivery `json:"delivery,omitempty"`

	// +kubebuilder:validation:Required
	// Request represents the OpenAI-compatible chat completion payload fields.
	Request AIRequest `json:"request"`
}

// AITriggerSpec defines the desired state of AITrigger.
type AITriggerSpec struct {
	TriggerSpec `json:",inline"`
	AIModel     `json:",inline"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="ErrorTime",type="string",JSONPath=".status.errorTime"
// +kubebuilder:printcolumn:name="ErrorReason",type="string",JSONPath=".status.errorReason"
// +kubebuilder:printcolumn:name="ErrorResourceVersion",type="string",JSONPath=".status.errorResourceVersion"

// AITrigger is the Schema for the aitriggers API.
type AITrigger struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AITriggerSpec `json:"spec,omitempty"`
	Status TriggerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AITriggerList contains a list of AITrigger.
type AITriggerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AITrigger `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AITrigger{}, &AITriggerList{})
}
