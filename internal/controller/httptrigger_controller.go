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
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/facette/natsort"
	"github.com/go-logr/logr"
	"github.com/go-openapi/inflect"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	triggersv1 "github.com/mhmxs/serverless-kube-watch-trigger/api/v1"
)

type Watcher struct {
	Reconciler *HTTPTriggerReconciler
}

func (w *Watcher) Start(ctx context.Context) error {
	return w.Reconciler.WatchInit(ctx)
}

// HTTPTriggerReconciler reconciles a HTTPTrigger object
type HTTPTriggerReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	DynamicClient *dynamic.DynamicClient

	ctx                 context.Context
	runningTriggersLock sync.Mutex
	runningTriggers     map[string]func()
}

// +kubebuilder:rbac:groups=triggers.harikube.info,resources=httptriggers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=httptriggers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=httptriggers/finalizers,verbs=update

// +kubebuilder:rbac:groups="",resources=secrets;services,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the HTTPTrigger object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *HTTPTriggerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx).WithValues("controller", "httptrigger", "name", req.NamespacedName)

	trigger := triggersv1.HTTPTrigger{}
	if err := r.Get(ctx, req.NamespacedName, &trigger); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Trigger fetch failed")

		return ctrl.Result{}, err
	}

	r.runningTriggersLock.Lock()
	defer r.runningTriggersLock.Unlock()

	if trigger.DeletionTimestamp != nil || !trigger.DeletionTimestamp.IsZero() {
		logger.Info("Trigger deleted")

		if cancel, ok := r.runningTriggers[req.String()]; ok {
			cancel()
		}

		return ctrl.Result{}, nil
	} else if trigger.Generation == 1 && trigger.Status.LastGeneration == 0 {
		logger.Info("Trigger created")
	} else {
		if trigger.Status.ErrorTime.IsZero() && trigger.Status.LastGeneration == trigger.Generation {
			return ctrl.Result{}, nil
		}

		logger.Info("Trigger updated")
	}

	if cancel, ok := r.runningTriggers[req.String()]; ok {
		cancel()

		return ctrl.Result{}, nil
	}

	if err := r.createTrigger(req.String(), &trigger); err != nil {
		logger.Error(err, "Trigger initialization failed")

		return ctrl.Result{}, err
	}

	patchedTrigger := trigger.DeepCopy()
	patchedTrigger.Status.LastGeneration = trigger.Generation
	patchedTrigger.Status.ErrorTime = metav1.Time{}
	patchedTrigger.Status.ErrorReason = ""
	patchedTrigger.Status.ErrorResourceVersion = "0"
	if err := r.Status().Patch(ctx, patchedTrigger, client.MergeFrom(&trigger)); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Trigger status update failed")

		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

//nolint:gocyclo
func (r *HTTPTriggerReconciler) createTrigger(triggerRefName string, trigger *triggersv1.HTTPTrigger) error {
	resourceVersion := "0"
	if trigger.Status.ErrorResourceVersion != "" {
		resourceVersion = trigger.Status.ErrorResourceVersion
	}

	listOpts := metav1.ListOptions{
		ResourceVersion:     resourceVersion,
		TimeoutSeconds:      ptr.To(int64(60)),
		Watch:               true,
		AllowWatchBookmarks: false,
		LabelSelector:       strings.Join(trigger.Spec.LabelSelector, ","),
		FieldSelector:       strings.Join(trigger.Spec.FieldSelector, ","),
	}
	if trigger.Spec.SendInitialEvents {
		listOpts.SendInitialEvents = ptr.To(true)
		listOpts.ResourceVersionMatch = metav1.ResourceVersionMatchNotOlderThan
	}

	apiParts := strings.Split(trigger.Spec.Resource.APIVersion, "/")
	if len(apiParts) == 1 {
		apiParts = append(apiParts, apiParts[0])
		apiParts[0] = ""
	}
	gvr := schema.GroupVersionResource{
		Group:    apiParts[0],
		Version:  apiParts[1],
		Resource: inflect.Pluralize(strings.ToLower(trigger.Spec.Resource.Kind)),
	}
	gvk := schema.GroupVersionKind{
		Group:   apiParts[0],
		Version: apiParts[1],
		Kind:    trigger.Spec.Resource.Kind,
	}

	triggerEventTypes := slices.Clone(trigger.Spec.EventType)
	if len(triggerEventTypes) == 0 {
		triggerEventTypes = append(triggerEventTypes,
			triggersv1.EventTypeAdded,
			triggersv1.EventTypeModified,
			triggersv1.EventTypeDeleted,
		)
	}
	eventTypes := map[string]bool{}
	for _, eventType := range triggerEventTypes {
		eventTypes[string(eventType)] = true
	}

	depFetchCtx, depFetchCancel := context.WithTimeout(r.ctx, time.Minute)
	defer depFetchCancel()

	var serviceProtocol string
	var servicePort int32
	if trigger.Spec.URL.Service != nil {
		endpointService := corev1.Service{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Spec.URL.Service.Namespace,
			Name:      trigger.Spec.URL.Service.Name,
		}, &endpointService); err != nil {
			return err
		}

		servicePort = 0
		serviceProtocol = trigger.Spec.URL.Service.PortName
		for _, port := range endpointService.Spec.Ports {
			if port.Name == trigger.Spec.URL.Service.PortName {
				servicePort = port.Port
			}
		}
		if servicePort == 0 {
			servicePort = endpointService.Spec.Ports[0].Port
			serviceProtocol = endpointService.Spec.Ports[0].Name
		}
		if serviceProtocol == "" {
			serviceProtocol = "http"
		}
	}

	var userAuthPassword string
	if trigger.Spec.Auth.BasicAuth != nil {
		passwordSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Auth.BasicAuth.PasswordRef.Name,
		}, &passwordSecret); err != nil {
			return err
		}
		userAuthPassword = string(passwordSecret.Data[trigger.Spec.Auth.BasicAuth.PasswordRef.Key])
	}

	headerSecrets := map[string]string{}
	for k, v := range trigger.Spec.Headers.FromSecretRef {
		headerSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      v.Name,
		}, &headerSecret); err != nil {
			return err
		}
		headerSecrets[k] = string(headerSecret.Data[v.Key])
	}

	var signature []byte
	if trigger.Spec.Body.Signature.KeySecretRef.Name != "" {
		signatureSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Body.Signature.KeySecretRef.Name,
		}, &signatureSecret); err != nil {
			return err
		}
		signature = signatureSecret.Data[trigger.Spec.Body.Signature.KeySecretRef.Key]
	}

	httpTransport := &http.Transport{
		MaxIdleConns:    int(trigger.Spec.Concurrency),
		IdleConnTimeout: time.Minute,
	}
	if trigger.Spec.Auth.TLS != nil {
		caSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Auth.TLS.CARef.Name,
		}, &caSecret); err != nil {
			return err
		}

		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caSecret.Data[trigger.Spec.Auth.TLS.CARef.Key]); !ok {
			return fmt.Errorf("error appending CA cert to pool")
		}

		certSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Auth.TLS.CertRef.Name,
		}, &certSecret); err != nil {
			return err
		}

		keySecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Auth.TLS.KeyRef.Name,
		}, &keySecret); err != nil {
			return err
		}

		clientCert, err := tls.X509KeyPair(
			certSecret.Data[trigger.Spec.Auth.TLS.CertRef.Key],
			keySecret.Data[trigger.Spec.Auth.TLS.KeyRef.Key],
		)
		if err != nil {
			return err
		}

		httpTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: trigger.Spec.Auth.TLS.InsecureSkipVerify,
			RootCAs:            caCertPool,
			Certificates:       []tls.Certificate{clientCert},
		}
	}
	httpClient := &http.Client{
		Timeout:   trigger.Spec.Delivery.Timeout.Duration,
		Transport: httpTransport,
	}

	resourceClient := r.DynamicClient.Resource(gvr)
	watchClients := []dynamic.ResourceInterface{}
	if len(trigger.Spec.Namespaces) != 0 {
		for _, namespace := range trigger.Spec.Namespaces {
			watchClients = append(watchClients, resourceClient.Namespace(namespace))
		}
	} else {
		watchClients = append(watchClients, resourceClient)
	}

	ctx, cancel := context.WithCancel(r.ctx)
	r.runningTriggers[triggerRefName] = cancel

	watchers := []watch.Interface{}
	for _, watchClient := range watchClients {
		watcher, err := watchClient.Watch(ctx, listOpts)
		if err != nil {
			for _, watcher := range watchers {
				watcher.Stop()
			}

			cancel()

			return err
		}

		watchers = append(watchers, watcher)
	}

	cases := make([]reflect.SelectCase, len(watchers))
	for i, w := range watchers {
		cases[i] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(w.ResultChan()),
		}
	}
	cases = append(cases, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(ctx.Done()),
	})

	lastResourceVersion := atomic.Pointer[string]{}
	lastResourceVersion.Store(ptr.To("0"))

	handleError := func(err error, logger logr.Logger) {
		r.runningTriggersLock.Lock()
		defer r.runningTriggersLock.Unlock()

		if cancel, ok := r.runningTriggers[triggerRefName]; ok {
			logger.Error(err, "Watcher closed")

			go func() {
				patchedTrigger := trigger.DeepCopy()
				patchedTrigger.Status.ErrorTime = metav1.Now()
				patchedTrigger.Status.ErrorReason = err.Error()
				patchedTrigger.Status.ErrorResourceVersion = *lastResourceVersion.Load()

				for {
					patchCtx, patchCancel := context.WithTimeout(r.ctx, time.Minute)
					if err := r.Status().Patch(patchCtx, patchedTrigger, client.MergeFrom(trigger)); err != nil && !apierrors.IsNotFound(err) {
						logger.Error(err, "Trigger status update failed")

						patchCancel()

						<-time.After(time.Second)

						continue
					}

					logger.Info("Trigger status successfully updated")

					patchCancel()

					break
				}
			}()

			cancel()
			delete(r.runningTriggers, triggerRefName)

			for _, w := range watchers {
				w.Stop()
			}
		}
	}

	logger := logf.FromContext(ctx).WithValues("trigger", triggerRefName, "grv", gvr.String())
	logger.Info("Watcher started")

	for i := 1; i <= int(trigger.Spec.Concurrency); i++ {
		go func() {
			for {
				_, data, ok := reflect.Select(cases)
				if !ok {
					handleError(fmt.Errorf("closed channel"), logger)

					return
				}

				eventVal := data.Interface()
				event := eventVal.(watch.Event)

				if event.Type == watch.Error {
					handleError(fmt.Errorf("error event received"), logger)

					return
				} else if event.Object == nil {
					continue
				} else if _, ok := eventTypes[string(event.Type)]; !ok {
					continue
				}

				event.Object.GetObjectKind().SetGroupVersionKind(gvk)

				unstructuredObj, ok := event.Object.(*unstructured.Unstructured)
				if !ok {
					handleError(fmt.Errorf("event conversion to unstructured failed"), logger)

					return
				}

				if trigger.Spec.EventFilter != "" {
					renderer, err := template.New("filter_template").Parse(fmt.Sprintf("{{if %s}}true{{end}}", trigger.Spec.EventFilter))
					if err != nil {
						handleError(err, logger)

						return
					}

					var renderedMatch bytes.Buffer
					if err = renderer.Execute(&renderedMatch, unstructuredObj.Object); err != nil {
						handleError(err, logger)

						return
					}
					if renderedMatch.String() != "true" {
						continue
					}
				}

				var url string
				switch {
				case trigger.Spec.URL.Static != nil:
					url = *trigger.Spec.URL.Static
				case trigger.Spec.URL.Template != nil:
					renderer, err := template.New("url_template").Parse(*trigger.Spec.URL.Template)
					if err != nil {
						handleError(err, logger)

						return
					}

					var renderedURL bytes.Buffer
					if err := renderer.Execute(&renderedURL, unstructuredObj.Object); err != nil {
						handleError(err, logger)

						return
					}
					url = renderedURL.String()
				case trigger.Spec.URL.Service != nil:
					var uri string
					switch {
					case trigger.Spec.URL.Service.URI.Static != nil:
						uri = *trigger.Spec.URL.Service.URI.Static
					case trigger.Spec.URL.Service.URI.Template != nil:
						renderer, err := template.New("uri_template").Parse(*trigger.Spec.URL.Service.URI.Template)
						if err != nil {
							handleError(err, logger)

							return
						}

						var renderedURI bytes.Buffer
						if err := renderer.Execute(&renderedURI, unstructuredObj.Object); err != nil {
							handleError(err, logger)

							return
						}
					default:
						handleError(fmt.Errorf("missing URI generation strategy"), logger)

						return
					}

					url = fmt.Sprintf("%s://%s.%s:%d/%s",
						serviceProtocol,
						trigger.Spec.URL.Service.Name,
						trigger.Spec.URL.Service.Namespace,
						servicePort,
						strings.TrimPrefix(uri, "/"),
					)
				default:
					// TODO Ingress, gateway
					handleError(fmt.Errorf("missing URL generation strategy"), logger)

					return
				}

				body := ""
				if trigger.Spec.Body.Template != "" {
					renderer, err := template.New("body_template_").Parse(trigger.Spec.Body.Template)
					if err != nil {
						handleError(err, logger)

						return
					}

					var renderedBody bytes.Buffer
					if err := renderer.Execute(&renderedBody, unstructuredObj.Object); err != nil {
						handleError(err, logger)

						return
					}
					body = renderedBody.String()
				}

				contentType := "application/json"
				if trigger.Spec.Body.ContentType != "" {
					contentType = trigger.Spec.Body.ContentType
				}
				headers := map[string]string{
					"Content-Type": contentType,
				}
				maps.Copy(headers, trigger.Spec.Headers.Static)
				for k, v := range trigger.Spec.Headers.Template {
					renderer, err := template.New("header_template_" + k).Parse(v)
					if err != nil {
						handleError(err, logger)

						return
					}

					var renderedHeader bytes.Buffer
					if err := renderer.Execute(&renderedHeader, unstructuredObj.Object); err != nil {
						handleError(err, logger)

						return
					}
					headers[k] = renderedHeader.String()
				}
				for k := range trigger.Spec.Headers.FromSecretRef {
					headers[k] = headerSecrets[k]
				}

				switch {
				case trigger.Spec.Body.Signature.HMAC != nil:
					var hash func() hash.Hash
					switch trigger.Spec.Body.Signature.HMAC.HashType {
					case triggersv1.SignatureHashTypeSHA256:
						hash = sha256.New
					case triggersv1.SignatureHashTypeSHA512:
						hash = sha512.New
					}

					hasher := hmac.New(hash, signature)
					hasher.Write([]byte(body))
					signatureBytes := hasher.Sum(nil)

					headers[trigger.Spec.Body.Signature.Header] = hex.EncodeToString(signatureBytes)
				}

				var retryErr error
				for i := 0; i <= int(trigger.Spec.Delivery.Retries); i++ {
					timeout := trigger.Spec.Delivery.Timeout.Duration
					if timeout == 0 {
						timeout = 10 * time.Second
					}
					reqCtx, reqCancel := context.WithTimeout(ctx, timeout)

					req, err := http.NewRequestWithContext(reqCtx, string(trigger.Spec.Method), url, strings.NewReader(body))
					if err != nil {
						handleError(err, logger)
						reqCancel()

						return
					}

					if trigger.Spec.Auth.BasicAuth != nil {
						req.SetBasicAuth(trigger.Spec.Auth.BasicAuth.User, userAuthPassword)
					}

					for k, v := range headers {
						req.Header.Add(k, v)
					}

					metadata := unstructuredObj.Object["metadata"].(map[string]interface{})

					resp, err := httpClient.Do(req)
					if err != nil {
						logger.Error(err, "Endpoint call failed", "name", metadata["name"], "namespace", metadata["namespace"], "resourceVersion", metadata["resourceVersion"])

						retryErr = err

						reqCancel()

						<-time.After(time.Second)

						continue
					} else if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
						if resp == nil {
							retryErr = errors.New("missing response")
						} else {
							retryErr = fmt.Errorf("status code is %d", resp.StatusCode)
						}

						logger.Error(retryErr, "Endpoint call failed", "name", metadata["name"], "namespace", metadata["namespace"], "resourceVersion", metadata["resourceVersion"])

						reqCancel()

						<-time.After(time.Second)

						continue
					}

					logger.Info("Endpoint successfully called", "name", metadata["name"], "namespace", metadata["namespace"], "resourceVersion", metadata["resourceVersion"])

					for {
						rv := metadata["resourceVersion"].(string)
						lrv := lastResourceVersion.Load()

						if natsort.Compare(rv, *lrv) {
							break
						} else if lastResourceVersion.CompareAndSwap(lrv, &rv) {
							break
						}
					}

					reqCancel()
					if err := resp.Body.Close(); err != nil {
						handleError(err, logger)

						return
					}

					break
				}

				if retryErr != nil {
					handleError(fmt.Errorf("retry failed: %w", retryErr), logger)

					return
				}
			}
		}()
	}

	return nil
}

func (r *HTTPTriggerReconciler) WatchInit(ctx context.Context) error {
	r.runningTriggersLock.Lock()
	defer r.runningTriggersLock.Unlock()

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	existingTriggers := triggersv1.HTTPTriggerList{}
	if err := r.List(ctx, &existingTriggers); err != nil {
		return err
	}

	for _, trigger := range existingTriggers.Items {
		if err := r.createTrigger(trigger.Namespace+"/"+trigger.Name, &trigger); err != nil {
			for _, tc := range r.runningTriggers {
				tc()
			}

			return err
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *HTTPTriggerReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	r.ctx = ctx
	r.runningTriggersLock = sync.Mutex{}
	r.runningTriggers = map[string]func(){}

	go func() {
		<-ctx.Done()

		r.runningTriggersLock.Lock()
		defer r.runningTriggersLock.Unlock()

		for _, c := range r.runningTriggers {
			c()
		}
	}()

	return ctrl.NewControllerManagedBy(mgr).
		For(&triggersv1.HTTPTrigger{}).
		Named("httptrigger").
		WithOptions(controller.Options{
			NeedLeaderElection:      ptr.To(true),
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
			Logger:                  mgr.GetLogger(),
		}).
		Complete(r)
}
