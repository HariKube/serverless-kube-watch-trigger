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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PiAgentSpec describes how to execute an embedded pi agent inside a Kubernetes Job.
type PiAgentSpec struct {
	// +kubebuilder:validation:Required
	// Image is the container image used for spawned pi agent Jobs.
	Image string `json:"image"`

	// +kubebuilder:validation:Required
	// ConfigSecretRef references the Secret mounted into ~/.pi/agent for the spawned worker.
	// The Secret must provide settings.json, models.json, models-store.json, and auth.json keys.
	ConfigSecretRef corev1.LocalObjectReference `json:"configSecretRef"`

	// +kubebuilder:validation:Required
	// PromptsConfigMapRef references the ConfigMap mounted into ~/.pi/agent/prompts.
	PromptsConfigMapRef corev1.LocalObjectReference `json:"promptsConfigMapRef"`

	// +kubebuilder:validation:Required
	// SkillsConfigMapRef references the ConfigMap mounted into ~/.pi/agent/skills.
	SkillsConfigMapRef corev1.LocalObjectReference `json:"skillsConfigMapRef"`

	// +kubebuilder:validation:Optional
	// Provider selects the pi provider used by the spawned worker Job.
	Provider string `json:"provider,omitempty"`

	// +kubebuilder:validation:Optional
	// Model selects the pi model used by the spawned worker Job.
	Model string `json:"model,omitempty"`

	// +kubebuilder:validation:Optional
	// WorkingDir is the working directory used by the spawned worker Job.
	WorkingDir string `json:"workingDir,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=true
	// NoExtensions disables loading ambient pi extensions for the spawned worker Job.
	NoExtensions bool `json:"noExtensions,omitempty"`

	// +kubebuilder:validation:Optional
	// Extensions explicitly loads pi extensions for the spawned worker Job.
	Extensions []string `json:"extensions,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default:="10m"
	// +kubebuilder:validation:Format=duration
	// Timeout limits the total runtime of the spawned worker Job.
	Timeout metav1.Duration `json:"timeout,omitempty"`

	// +kubebuilder:validation:Optional
	// ServiceAccountName overrides the ServiceAccount used by spawned Jobs.
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// +kubebuilder:validation:Optional
	// ImagePullPolicy controls when the Job image is pulled.
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// +kubebuilder:validation:Optional
	// Env adds extra environment variables to the worker container.
	Env []corev1.EnvVar `json:"env,omitempty"`

	// +kubebuilder:validation:Optional
	// EnvFrom imports environment variables from ConfigMaps or Secrets into the worker container.
	EnvFrom []corev1.EnvFromSource `json:"envFrom,omitempty"`

	// +kubebuilder:validation:Optional
	// Resources configures CPU and memory requests and limits for the worker container.
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// BackoffLimit configures Kubernetes Job retries for a failed worker.
	BackoffLimit *int32 `json:"backoffLimit,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// ActiveDeadlineSeconds limits the total execution time of a worker Job.
	ActiveDeadlineSeconds *int64 `json:"activeDeadlineSeconds,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// TTLSecondsAfterFinished controls automatic cleanup of completed Jobs.
	TTLSecondsAfterFinished *int32 `json:"ttlSecondsAfterFinished,omitempty"`
}

// PiTriggerStatus defines the observed state of PiTrigger.
type PiTriggerStatus struct {
	// Phase is the observed operational state of the trigger watcher. It is reported as
	// Running whenever a watcher is established and set to Error whenever the
	// watcher collapses or the trigger cannot be initialized.
	// +kubebuilder:validation:Optional
	Phase TriggerPhase `json:"phase,omitempty"`

	ErrorTime            metav1.Time `json:"errorTime,omitempty"`
	ErrorReason          string      `json:"errorReason,omitempty"`
	ErrorResourceVersion string      `json:"errorResourceVersion,omitempty"`
	LastGeneration       int64       `json:"lastGeneration,omitempty"`
}

// PiTriggerSpec defines the desired state of PiTrigger.
type PiTriggerSpec struct {
	TriggerSpec `json:",inline"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// MaxJobs limits the number of active worker Jobs for this trigger. Zero means unlimited.
	MaxJobs int32       `json:"maxJobs,omitempty"`
	Agent   PiAgentSpec `json:"agent"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="ErrorTime",type="string",JSONPath=".status.errorTime"
// +kubebuilder:printcolumn:name="ErrorReason",type="string",JSONPath=".status.errorReason"
// +kubebuilder:printcolumn:name="ErrorResourceVersion",type="string",JSONPath=".status.errorResourceVersion"

// PiTrigger is the Schema for the pitriggers API.
type PiTrigger struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PiTriggerSpec   `json:"spec,omitempty"`
	Status PiTriggerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PiTriggerList contains a list of PiTrigger.
type PiTriggerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PiTrigger `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PiTrigger{}, &PiTriggerList{})
}
