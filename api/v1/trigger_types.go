package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:validation:Enum=ADDED;MODIFIED;DELETED
type EventType string

// +kubebuilder:validation:Enum=GET;POST;PUT;PATCH
type Method string

// +kubebuilder:validation:Enum=SHA256;SHA512
type SignatureHashType string

const (
	EventTypeAdded    EventType = "ADDED"
	EventTypeModified EventType = "MODIFIED"
	EventTypeDeleted  EventType = "DELETED"

	MethodGet   Method = "GET"
	MethodPost  Method = "POST"
	MethodPut   Method = "PUT"
	MethodPatch Method = "PATCH" // RFC 5789

	SignatureHashTypeSHA256 SignatureHashType = "SHA256"
	SignatureHashTypeSHA512 SignatureHashType = "SHA512"
)

// TriggerSpec defines the desired state of Trigger.
type TriggerSpec struct {
	// +kubebuilder:validation:Required
	// Resource represents the object kind.
	Resource metav1.TypeMeta `json:"resource"`

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
	// EventFilter represents a filter expression, follows Go template syntax. Example: ne .status.availableReplicas 0.
	EventFilter string `json:"eventFilter,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=1
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// Concurency represent the number of parallel triggers.
	Concurrency uint8 `json:"concurrency,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=false
	// SendInitialEvents represents initial object state triggers.
	SendInitialEvents bool `json:"sendInitialEvents,omitempty"`
}

// HTTP represents HTTP based trigger details.
type HTTP struct {
	// +kubebuilder:validation:Required
	// URL Represents the URL generator strategy.
	URL URL `json:"url"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=POST
	Method Method `json:"method,omitempty"`

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

// URL Represents the URL generator strategy.
type URL struct {
	// +kubebuilder:validation:Optional
	// Static represents a static endpoint.
	Static *string `json:"static,omitempty"`

	// +kubebuilder:validation:Optional
	// Template represents the URL template of the endpoint, follows Go template syntax. Example: https://gateway.example.com/function/foo/{{ .metadata.name }}.
	Template *string `json:"template,omitempty"`

	// +kubebuilder:validation:Optional
	// Service represents a service based endpoint.
	Service *Service `json:"service,omitempty"`
}

// Service represents a service based endpoint.
type Service struct {
	corev1.LocalObjectReference `json:",inline"`

	// +kubebuilder:validation:Optional
	// Namespace represents the namespace of service.
	Namespace string `json:"namespace,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=https
	// PortName represents the name of port. The name of the port become the protocol of the call.
	PortName string `json:"portName,omitempty"`

	// +kubebuilder:validation:Required
	// URI Represents the URI generator strategy.
	URI URI `json:"uri"`
}

// URL Represents the URL generator strategy.
type URI struct {
	// +kubebuilder:validation:Optional
	// Static represents a static endpoint.
	Static *string `json:"static,omitempty"`

	// +kubebuilder:validation:Optional
	// Template represents the URI template of the endpoint, follows Go template syntax. Example: /function/foo/{{ .metadata.name }}.
	Template *string `json:"template,omitempty"`
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
	// CertRef represents the certification secret reference.
	CertRef corev1.SecretKeySelector `json:"certRef"`

	// +kubebuilder:validation:Required
	// KeyRef represents the key secret reference.
	KeyRef corev1.SecretKeySelector `json:"keyRef"`

	// +kubebuilder:validation:Optional
	// InsecureSkipVerify represents verification of insecure TLS certs.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// Headers represends extra headers of the request.
type Headers struct {
	// +kubebuilder:validation:Optional
	// Static represents static header.
	Static map[string]string `json:"static,omitempty"`

	// +kubebuilder:validation:Optional
	// Template represents dynamic header, follows Go template syntax. Example: X-Resource-Name: "{{ .metadata.name }}"
	Template map[string]string `json:"template,omitempty"`

	// +kubebuilder:validation:Optional
	// FromSecret represents header from secret.
	FromSecretRef map[string]corev1.SecretKeySelector `json:"fromSecretRef,omitempty"`
}

// Body represents the body of the request.
type Body struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=application/json
	// ContentType represents the content type of the body.
	ContentType string `json:"contentType,omitempty"`

	// +kubebuilder:validation:Optional
	// Template represents the template to generate body.
	Template string `json:"template,omitempty"`

	// +kubebuilder:validation:Optional
	// Signature represents message signature generator.
	Signature Signature `json:"signature,omitempty"`
}

// Signature represents message signature generator.
type Signature struct {
	// +kubebuilder:validation:Required
	// Header represents the header key of the signature.
	Header string `json:"header"`

	// +kubebuilder:validation:Required
	// KeySecretRef represents signature key secret.
	KeySecretRef corev1.SecretKeySelector `json:"keySecretRef,omitempty"`

	// +kubebuilder:validation:Optional
	// HMAC represents HMAC message signature generator.
	HMAC *HMAC `json:"hmac,omitempty"`
}

type HMAC struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=SHA256
	// HashType represents the hash type.
	HashType SignatureHashType `json:"hashType,omitempty"`
}

// Delivery represents the delivery details.
type Delivery struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:default:='10s'
	// +kubebuilder:validation:Format=duration
	// Timeout represents the timeout of the request.
	Timeout metav1.Duration `json:"timeout,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default:=1
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// Retries represents the retries of the request on failure.
	Retries uint8 `json:"retries,omitempty"`
}

// TriggerStatus defines the observed state of Trigger.
type TriggerStatus struct {
	ErrorTime            metav1.Time `json:"errorTime,omitempty"`
	ErrorReason          string      `json:"errorReason,omitempty"`
	ErrorResourceVersion string      `json:"errorResourceVersion,omitempty"`
	LastGeneration       int64       `json:"lastGeneration,omitempty"`
}
