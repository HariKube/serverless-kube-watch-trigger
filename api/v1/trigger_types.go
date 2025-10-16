package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:validation:Enum=ADDED;MODIFIED;DELETED
type EventType string

// +kubebuilder:validation:Enum=SHA256
type SignatureAlgoType string

const (
	EventTypeAdded    EventType = "ADDED"
	EventTypeModified EventType = "MODIFIED"
	EventTypeDeleted  EventType = "DELETED"

	SignatureAlgoTypeSHA256 SignatureAlgoType = "SHA256"
)

// TriggerSpec defines the desired state of Trigger.
type TriggerSpec struct {
	// +kubebuilder:validation:Required
	// Meta represents the object kind.
	Meta metav1.TypeMeta `json:"meta"`

	// +kubebuilder:validation:Optional
	// Namespaces represents the namespaces to watch.
	Namespaces []string `json:"namespaces,omitempty"`

	// +kubebuilder:validation:Optional
	// LabelSelector represents list of label selectors.
	LabelSelector []string `json:"labelSelectors,omitempty"`

	// +kubebuilder:validation:Optional
	// FieldSelector represents list of field selectors.
	FieldSelector []string `json:"fieldSelectors,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default:={"ADDED","MODIFIED","DELETED"}
	// EventType represents the type of events to trigger.
	EventType []EventType `json:"eventTypes,omitempty"`

	// +kubebuilder:validation:Optional
	// EventFilter represents a filter expression. Example: old.status.availableReplicas != new.status.availableReplicas.
	EventFilter string `json:"eventFilter,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=1
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// Concurency represent the number of parallel triggers.
	Concurrency uint8 `json:"concurrency,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=false
	// SendInitialEvents represents initial object state triggers.
	SendInitialEvents bool `json:"sendInitialEvents,omitempty"`
}

// HTTPTrigger defines HTTP based trigger details.
type HTTP struct {
	// +kubebuilder:validation:Required
	// Endpoint represents different endpoint generators.
	Endpoint Endpoint `json:"endpoint"`
}

// Endpoint represents different endpoint generators.
type Endpoint struct {
	// +kubebuilder:validation:Optional
	// Static represents a fixed endpoint.
	Static *string `json:"static,omitempty"`

	// +kubebuilder:validation:Optional
	// URLTemplate represents the URL template of the endpoint. Example: https://gateway.example.com/function/foo/{{ .metadata.name }}.
	URLTemplate *string `json:"uriTemplate,omitempty"`

	// +kubebuilder:validation:Optional
	// Service represents a service based endpoint.
	Service *Service `json:"service,omitempty"`

	// +kubebuilder:validation:Optional
	// Auth represents different authentication methods.
	Auth Auth `json:"auth,omitempty"`

	// +kubebuilder:validation:Optional
	// Headers represends extra headers of the request.
	Headers Headers `json:"headers,omitempty"`

	// +kubebuilder:validation:Optional
	// Body represents the body of the request.
	Body Body `json:"body,omitempty"`

	// +kubebuilder:validation:Optional
	// Delivery represents the delivery details.
	Delivery Delivery `json:"delivery,omitempty"`
}

// Service represents a service based endpoint.
type Service struct {
	corev1.LocalObjectReference `json:",inline"`

	// +kubebuilder:validation:Optional
	// Namespace represents the namespace of service.
	Namespace string `json:"static,omitempty"`

	// +kubebuilder:validation:Optional
	// URITemplate represents the URI template of the endpoint. Example: /function/foo/{{ .metadata.name }}.
	URITemplate string `json:"uriTemplate,omitempty"`
}

// Auth represents different authentication methods.
type Auth struct {
	// +kubebuilder:validation:Optional
	// BasicAuth represents the basic authentication details.
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`

	// +kubebuilder:validation:Optional
	// TLS represents TLS authentication details.
	TLS *TLS `json:"tls,omitempty"`
}

// BasicAuth represents the basic authentication details.
type BasicAuth struct {
	// +kubebuilder:validation:Required
	// User represents the name of the user.
	User string `json:"user"`

	// +kubebuilder:validation:Required
	// SecretKeyRef represents the password secret reference.
	PasswordRef corev1.SecretKeySelector `json:"secretKeyRef"`
}

// TLS represents TLS authentication details.
type TLS struct {
	// +kubebuilder:validation:Required
	// CARef represents the CA secret reference.
	CARef corev1.SecretKeySelector `json:"caRef"`

	// +kubebuilder:validation:Required
	// KeyRef represents the key secret reference.
	KeyRef corev1.SecretKeySelector `json:"keyRef"`
}

// Headers represends extra headers of the request.
type Headers struct {
	// +kubebuilder:validation:Optional
	// Static represents fixed header.
	Static map[string]string `json:"static,omitempty"`

	// +kubebuilder:validation:Optional
	// Template represents dynamic header. Example: X-Resource-Name: "{{ .metadata.name }}"
	Template map[string]string `json:"template,omitempty"`

	// +kubebuilder:validation:Optional
	// FromSecret represents header from secret.
	FromSecretRef corev1.SecretKeySelector `json:"fromSecretRef,omitempty"`
}

// Body represents the body of the request.
type Body struct {
	// +kubebuilder:validation:Optional
	// ContentType represents the content type of the body.
	ContentType string `json:"contentType,omitempty"`

	// +kubebuilder:validation:Optional
	// Template represents the template to generate body.
	Template string `json:"template,omitempty"`
}

// Delivery represents the delivery details.
type Delivery struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=duration
	// Timeout represents the timeout of the request.
	Timeout metav1.Duration `json:"compactInterval,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// Retries represents the retries of the request on failure.
	Retries uint8 `json:"retries,omitempty"`

	// +kubebuilder:validation:Optional
	// Signature represents message signature generator.
	Signature Signature `json:"signature,omitempty"`
}

// Signature represents message signature generator.
type Signature struct {
	// +kubebuilder:validation:Optional
	// HMAC represents HMAC message signature generator.
	HMAC *HMAC `json:"hmac,omitempty"`
}

type HMAC struct {
	// +kubebuilder:validation:Required
	// Header represents the header key of the signature.
	Header string `json:"hmac"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=SHA256
	// Algorythm represents the has algorythm type.
	Algorythm SignatureAlgoType `json:"algorythm,omitempty"`

	// +kubebuilder:validation:Required
	// KeySecretRef represents signature key secret.
	KeySecretRef corev1.SecretKeySelector `json:"keySecretRef,omitempty"`
}
