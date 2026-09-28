package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-openapi/inflect"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
	"github.com/harikube/serverless-kube-watch-trigger/pkg/lease"
)

const trueString = "true"

const kubeconfigKey = "kubeconfig"

const (
	filterTemplateName = "filter_template"
	urlTemplateName    = "url_template"
	uriTemplateName    = "uri_template"

	triggerEventReasonWatcherClosed = "WatcherClosed"
	triggerEventReasonCallFailed    = "TriggerCallFailed"
	triggerEventTypeCallFailed      = corev1.EventTypeWarning
	triggerEventTypeWatcherClosed   = corev1.EventTypeWarning
)

type kubeGetter interface {
	Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error
}

// acquireAnnotationLease claims the opt-in per-trigger reconcile lease that is
// stored on the trigger itself as triggers.harikube.info/lock-timestamp. It is
// only used when spec.lockDuration is set; a zero duration disables annotation
// locking entirely and the reconcile is not serialized across replicas.
//
// The returned result is non-nil when the lease is currently held by somebody
// else and the reconcile has to be requeued. On success the caller must hand
// the lease back with lease.ClearLease once the trigger reached its target
// state, otherwise the lease is left to expire on its own.
func acquireAnnotationLease(
	ctx context.Context,
	logger logr.Logger,
	cl client.Client,
	obj client.Object,
	lockDuration time.Duration,
) (bool, *ctrl.Result, error) {
	if lockDuration <= 0 {
		return false, nil, nil
	}

	leaseResult, err := lease.TryAcquireLease(ctx, cl, obj, time.Now().UTC(), lockDuration)
	if err != nil {
		logger.Error(err, "Trigger annotation lease acquisition failed", "annotation", lease.AnnotationKey)

		return false, nil, err
	}
	if leaseResult.RequeueAfter > 0 {
		logger.V(1).Info("Trigger annotation lease still active, requeueing", "annotation", lease.AnnotationKey, "requeueAfter", leaseResult.RequeueAfter.String())

		return false, &ctrl.Result{RequeueAfter: leaseResult.RequeueAfter}, nil
	}
	if leaseResult.Conflict {
		retryAfter := lease.ConflictRetryDelay()
		logger.V(1).Info("Trigger annotation lease was won by another replica, requeueing", "annotation", lease.AnnotationKey, "requeueAfter", retryAfter.String())

		return false, &ctrl.Result{RequeueAfter: retryAfter}, nil
	}

	return leaseResult.Acquired, nil, nil
}

// releaseAnnotationLease hands a lease acquired by acquireAnnotationLease back.
func releaseAnnotationLease(ctx context.Context, logger logr.Logger, cl client.Client, obj client.Object) error {
	if err := lease.ClearLease(ctx, cl, obj); err != nil {
		logger.Error(err, "Trigger annotation lease release failed", "annotation", lease.AnnotationKey)

		return err
	}

	return nil
}

// clearExpiredAnnotationLease drops an annotation lease that was left behind by
// a reconcile which never released it. A lease that is still valid is kept so a
// replica that is currently mid-reconcile does not lose its claim.
func clearExpiredAnnotationLease(ctx context.Context, logger logr.Logger, cl client.Client, obj client.Object, lockDuration time.Duration) error {
	if _, ok := obj.GetAnnotations()[lease.AnnotationKey]; !ok {
		return nil
	}
	if remaining := lease.ActiveLeaseRemaining(obj, time.Now().UTC(), lockDuration); remaining > 0 {
		return nil
	}

	return releaseAnnotationLease(ctx, logger, cl, obj)
}

func toJson(v any) string {
	a, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("Error marshaling to JSON: %v", err)
	}
	return string(a)
}

func triggerResourceVersion(errorResourceVersion string) string {
	if errorResourceVersion == "" {
		return "0"
	}
	return errorResourceVersion
}

func buildTriggerResourceInfo(resource metav1.TypeMeta) (schema.GroupVersionResource, schema.GroupVersionKind) {
	apiParts := strings.Split(resource.APIVersion, "/")
	if len(apiParts) == 1 {
		apiParts = []string{"", apiParts[0]}
	}

	return schema.GroupVersionResource{
			Group:    apiParts[0],
			Version:  apiParts[1],
			Resource: inflect.Pluralize(strings.ToLower(resource.Kind)),
		}, schema.GroupVersionKind{
			Group:   apiParts[0],
			Version: apiParts[1],
			Kind:    resource.Kind,
		}
}

func buildTriggerEventTypes(triggerEventTypes []triggersv1.EventType) map[string]bool {
	eventTypes := slices.Clone(triggerEventTypes)
	if len(eventTypes) == 0 {
		eventTypes = []triggersv1.EventType{
			triggersv1.EventTypeAdded,
			triggersv1.EventTypeModified,
			triggersv1.EventTypeDeleted,
		}
	}

	allowed := make(map[string]bool, len(eventTypes))
	for _, eventType := range eventTypes {
		allowed[string(eventType)] = true
	}
	return allowed
}

func addCompiledTemplate(compiledTemplates map[string]*template.Template, name string, raw string, funcs template.FuncMap) error {
	renderer := template.New(name)
	if len(funcs) != 0 {
		renderer = renderer.Funcs(funcs)
	}

	parsed, err := renderer.Parse(raw)
	if err != nil {
		return err
	}

	compiledTemplates[name] = parsed
	return nil
}

func compileSharedTemplates(compiledTemplates map[string]*template.Template, eventFilter string, urlSpec triggersv1.URL, headers triggersv1.Headers) error {
	if eventFilter != "" {
		if err := addCompiledTemplate(compiledTemplates, filterTemplateName, fmt.Sprintf("{{if %s}}true{{end}}", eventFilter), nil); err != nil {
			return errors.Join(err, ErrInvalidTriggerContent, errors.New("failed to parse filter template"))
		}
	}
	if urlSpec.Template != nil {
		if err := addCompiledTemplate(compiledTemplates, urlTemplateName, *urlSpec.Template, nil); err != nil {
			return errors.Join(err, ErrInvalidTriggerContent, errors.New("failed to parse url template"))
		}
	}
	if urlSpec.Service != nil && urlSpec.Service.URI.Template != nil {
		if err := addCompiledTemplate(compiledTemplates, uriTemplateName, *urlSpec.Service.URI.Template, nil); err != nil {
			return errors.Join(err, ErrInvalidTriggerContent, errors.New("failed to parse uri template"))
		}
	}
	for key, value := range headers.Template {
		if err := addCompiledTemplate(compiledTemplates, "header_template_"+key, value, nil); err != nil {
			return errors.Join(err, ErrInvalidTriggerContent, fmt.Errorf("failed to parse header template: %s", key))
		}
	}

	return nil
}

func loadSecretBytes(ctx context.Context, getter kubeGetter, namespace string, selector corev1.SecretKeySelector) ([]byte, error) {
	secret := corev1.Secret{}
	if err := getter.Get(ctx, client.ObjectKey{Namespace: namespace, Name: selector.Name}, &secret); err != nil {
		return nil, err
	}
	return secret.Data[selector.Key], nil
}

func loadSecretString(ctx context.Context, getter kubeGetter, namespace string, selector corev1.SecretKeySelector) (string, error) {
	value, err := loadSecretBytes(ctx, getter, namespace, selector)
	if err != nil {
		return "", err
	}
	return string(value), nil
}

// getWatcherResourceClient returns a NamespaceableResourceInterface to be used by
// watcher loops for the requested resource GVR. If watcherSecret.Name is empty
// the provided localClient is returned; otherwise the function loads the
// kubeconfig bytes from the named Secret (data key "kubeconfig"), builds a
// dynamic client using that kubeconfig, and returns the resource client for gvr.
func getWatcherResourceClient(ctx context.Context, getter kubeGetter, namespace string, localClient dynamic.NamespaceableResourceInterface, watcherSecret corev1.LocalObjectReference, gvr schema.GroupVersionResource) (dynamic.NamespaceableResourceInterface, error) {
	if watcherSecret.Name == "" {
		return localClient, nil
	}

	kubeconfig, err := loadSecretBytes(ctx, getter, namespace, corev1.SecretKeySelector{LocalObjectReference: watcherSecret, Key: kubeconfigKey})
	if err != nil {
		return nil, err
	}
	if len(kubeconfig) == 0 {
		return nil, fmt.Errorf("secret %s missing %q data", watcherSecret.Name, kubeconfigKey)
	}

	cfg, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, err
	}
	normalizeLoopbackRESTConfigForInCluster(cfg)
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	return dyn.Resource(gvr), nil
}
func normalizeLoopbackRESTConfigForInCluster(cfg *rest.Config) {
	if cfg == nil || cfg.Host == "" {
		return
	}

	hostURL, err := url.Parse(cfg.Host)
	if err != nil {
		return
	}

	hostname := hostURL.Hostname()
	if hostname == "" {
		return
	}
	if hostname != "localhost" {
		ip := net.ParseIP(hostname)
		if ip == nil || !ip.IsLoopback() {
			return
		}
	}

	serviceHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	if serviceHost == "" {
		return
	}
	servicePort := os.Getenv("KUBERNETES_SERVICE_PORT")
	if servicePort == "" {
		servicePort = "443"
	}

	hostURL.Host = net.JoinHostPort(serviceHost, servicePort)
	cfg.Host = hostURL.String()
	if cfg.ServerName == "" {
		cfg.ServerName = "kubernetes.default.svc"
	}
}

func loadHeaderSecrets(ctx context.Context, getter kubeGetter, namespace string, refs map[string]corev1.SecretKeySelector) (map[string]string, error) {
	headerSecrets := make(map[string]string, len(refs))
	for key, selector := range refs {
		value, err := loadSecretString(ctx, getter, namespace, selector)
		if err != nil {
			return nil, err
		}
		headerSecrets[key] = value
	}
	return headerSecrets, nil
}

func resolveServiceEndpoint(ctx context.Context, getter kubeGetter, service *triggersv1.Service) (string, int32, error) {
	if service == nil {
		return "", 0, nil
	}

	endpointService := corev1.Service{}
	if err := getter.Get(ctx, client.ObjectKey{Namespace: service.Namespace, Name: service.Name}, &endpointService); err != nil {
		return "", 0, err
	}

	scheme := service.Scheme
	if scheme == "" {
		scheme = "http"
	}

	var portNumber int32
	for _, port := range endpointService.Spec.Ports {
		if port.Name == service.PortName {
			portNumber = port.Port
			break
		}
	}
	if portNumber == 0 && len(endpointService.Spec.Ports) != 0 {
		portNumber = endpointService.Spec.Ports[0].Port
	}

	return scheme, portNumber, nil
}

func normalizeConcurrency(concurrency uint8) uint8 {
	if concurrency == 0 {
		return 1
	}
	return concurrency
}

func normalizeHTTPTimeout(timeout time.Duration) time.Duration {
	if timeout == 0 {
		return 10 * time.Second
	}
	return timeout
}

func methodOrDefault(method triggersv1.Method) string {
	if method == "" {
		return http.MethodPost
	}
	return string(method)
}

func newTriggerHTTPTransport(ctx context.Context, getter kubeGetter, namespace string, tlsConfig *triggersv1.TLS, concurrency uint8) (*http.Transport, error) {
	normalizedConcurrency := normalizeConcurrency(concurrency)
	httpTransport := &http.Transport{
		MaxIdleConns:          int(normalizedConcurrency * 2),
		MaxIdleConnsPerHost:   int(normalizedConcurrency),
		MaxConnsPerHost:       int(normalizedConcurrency * 2),
		IdleConnTimeout:       time.Minute,
		ExpectContinueTimeout: time.Second,
	}
	if tlsConfig == nil {
		return httpTransport, nil
	}

	httpTransport.TLSHandshakeTimeout = 10 * time.Second

	caPEM, err := loadSecretBytes(ctx, getter, namespace, tlsConfig.CARef)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("error appending CA cert to pool")
	}

	certPEM, err := loadSecretBytes(ctx, getter, namespace, tlsConfig.CertRef)
	if err != nil {
		return nil, err
	}
	keyPEM, err := loadSecretBytes(ctx, getter, namespace, tlsConfig.KeyRef)
	if err != nil {
		return nil, err
	}

	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	httpTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
		RootCAs:            caCertPool,
		Certificates:       []tls.Certificate{clientCert},
	}

	return httpTransport, nil
}

func newTriggerHTTPClient(ctx context.Context, getter kubeGetter, namespace string, tlsConfig *triggersv1.TLS, timeout time.Duration, concurrency uint8) (*http.Client, error) {
	httpTransport, err := newTriggerHTTPTransport(ctx, getter, namespace, tlsConfig, concurrency)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: httpTransport,
	}, nil
}

func buildWatchClients(resourceClient dynamic.NamespaceableResourceInterface, namespaces []string) []dynamic.ResourceInterface {
	if len(namespaces) == 0 {
		return []dynamic.ResourceInterface{resourceClient}
	}

	watchClients := make([]dynamic.ResourceInterface, 0, len(namespaces))
	for _, namespace := range namespaces {
		watchClients = append(watchClients, resourceClient.Namespace(namespace))
	}
	return watchClients
}

func buildWatcherListOptions(resourceVersion string, sendInitialEvents bool, labelSelector []string, fieldSelector []string) metav1.ListOptions {
	return metav1.ListOptions{
		ResourceVersion:      resourceVersion,
		TimeoutSeconds:       ptr.To(int64(60)),
		Watch:                true,
		AllowWatchBookmarks:  true,
		SendInitialEvents:    ptr.To(sendInitialEvents),
		ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		LabelSelector:        strings.Join(labelSelector, ","),
		FieldSelector:        strings.Join(fieldSelector, ","),
	}
}

func stopWatchers(watchers []watch.Interface) {
	for _, watcher := range watchers {
		watcher.Stop()
	}
}

func openWatchers(ctx context.Context, watchClients []dynamic.ResourceInterface, listOpts metav1.ListOptions) ([]watch.Interface, error) {
	watchers := make([]watch.Interface, 0, len(watchClients))
	for _, watchClient := range watchClients {
		watcher, err := watchClient.Watch(ctx, listOpts)
		if err != nil {
			stopWatchers(watchers)
			return nil, err
		}
		watchers = append(watchers, watcher)
	}
	return watchers, nil
}

func buildWatcherSelectCases(watchers []watch.Interface, done <-chan struct{}) []reflect.SelectCase {
	cases := make([]reflect.SelectCase, len(watchers))
	for i, watcher := range watchers {
		cases[i] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(watcher.ResultChan()),
		}
	}
	return append(cases, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(done),
	})
}

func renderTemplateToString(compiledTemplates map[string]*template.Template, name string, data any) (string, error) {
	var rendered bytes.Buffer
	if err := compiledTemplates[name].Execute(&rendered, data); err != nil {
		return "", err
	}
	return rendered.String(), nil
}

func buildTriggerURL(urlSpec triggersv1.URL, compiledTemplates map[string]*template.Template, object map[string]any, serviceScheme string, servicePort int32) (string, error) {
	switch {
	case urlSpec.Static != nil:
		return *urlSpec.Static, nil
	case urlSpec.Template != nil:
		return renderTemplateToString(compiledTemplates, urlTemplateName, object)
	case urlSpec.Service != nil:
		var uri string
		switch {
		case urlSpec.Service.URI.Static != nil:
			uri = *urlSpec.Service.URI.Static
		case urlSpec.Service.URI.Template != nil:
			renderedURI, err := renderTemplateToString(compiledTemplates, uriTemplateName, object)
			if err != nil {
				return "", err
			}
			uri = renderedURI
		default:
			return "", fmt.Errorf("missing URI generation strategy")
		}

		return fmt.Sprintf("%s://%s.%s:%d/%s",
			serviceScheme,
			urlSpec.Service.Name,
			urlSpec.Service.Namespace,
			servicePort,
			strings.TrimPrefix(uri, "/"),
		), nil
	default:
		return "", fmt.Errorf("missing URL generation strategy")
	}
}

func buildTriggerHeaders(contentType string, headers triggersv1.Headers, headerSecrets map[string]string, compiledTemplates map[string]*template.Template, object map[string]any) (map[string]string, error) {
	renderedHeaders := map[string]string{
		"Content-Type": contentType,
	}
	maps.Copy(renderedHeaders, headers.Static)

	for key := range headers.Template {
		renderedHeader, err := renderTemplateToString(compiledTemplates, "header_template_"+key, object)
		if err != nil {
			return nil, err
		}
		renderedHeaders[key] = renderedHeader
	}
	for key := range headers.FromSecretRef {
		renderedHeaders[key] = headerSecrets[key]
	}

	return renderedHeaders, nil
}

func emitTriggerCallFailureEvent(recorder record.EventRecorder, trigger client.Object, triggerRefName, method, callURL string, eventType watch.EventType, metadata map[string]interface{}, err error) {
	if recorder == nil {
		return
	}

	recorder.Eventf(
		trigger,
		triggerEventTypeCallFailed,
		triggerEventReasonCallFailed,
		"Trigger call failed for %s: method=%s url=%s eventType=%s object=%s/%s resourceVersion=%s error=%q",
		triggerRefName,
		method,
		callURL,
		eventType,
		fmt.Sprint(metadata["namespace"]),
		fmt.Sprint(metadata["name"]),
		fmt.Sprint(metadata["resourceVersion"]),
		err,
	)
}

func handleTriggerWatcherError(
	controllerCtx context.Context,
	err error,
	logger logr.Logger,
	recorder record.EventRecorder,
	trigger client.Object,
	triggerRefName string,
	errorResourceVersion string,
	runningTriggersLock *sync.Mutex,
	runningTriggers map[string]func(),
	sessionStale <-chan struct{},
	stopWatchers func(),
	patchStatus func(context.Context, metav1.Time, string, string) (bool, error),
) {
	runningTriggersLock.Lock()
	defer runningTriggersLock.Unlock()

	cancel, ok := runningTriggers[triggerRefName]
	if !ok {
		return
	}

	select {
	case <-sessionStale:
		// The session was cancelled and possibly replaced by a newer one
		// (trigger update, deletion or shutdown); drop out without touching
		// shared state.
		return
	default:
	}

	logger.Error(err, "Watcher closed")

	errorTime := metav1.Now()
	errorReason := err.Error()

	go func() {
		for attempt := 0; ; attempt++ {
			// The controller context is cancelled on manager shutdown; a
			// worker must never keep retrying against a cancelled context.
			if controllerCtx.Err() != nil {
				return
			}

			if attempt > 0 {
				select {
				case <-sessionStale:
					// The session was cancelled (trigger update, deletion or
					// shutdown) while this worker was retrying; once cancelled
					// the recovery reconcile owns the trigger status and this
					// worker must stop patching.
					return
				default:
				}
			}

			patchCtx, patchCancel := context.WithTimeout(controllerCtx, time.Minute)
			applied, patchErr := patchStatus(patchCtx, errorTime, errorReason, errorResourceVersion)
			patchCancel()
			if patchErr != nil && !apierrors.IsNotFound(patchErr) {
				logger.Error(patchErr, "Trigger status update failed")

				<-time.After(time.Second)

				continue
			}

			if patchErr == nil && applied && recorder != nil {
				recorder.Eventf(
					trigger,
					triggerEventTypeWatcherClosed,
					triggerEventReasonWatcherClosed,
					"Watcher closed for %s: error=%q resourceVersion=%s errorTime=%s",
					triggerRefName,
					errorReason,
					errorResourceVersion,
					errorTime.UTC().Format(time.RFC3339),
				)
			}

			if applied {
				logger.Info("Trigger status successfully updated", "errorReason", errorReason, "errorResourceVersion", errorResourceVersion)
			}

			break
		}
	}()

	cancel()
	delete(runningTriggers, triggerRefName)
	stopWatchers()
}
