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
	"encoding/json"
	"fmt"
	"hash"
	"maps"
	"net/http"
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

// HTTPTriggerReconciler reconciles a HTTPTrigger object
type HTTPTriggerReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	DynamicClient *dynamic.DynamicClient

	Name string
	For  client.Object

	ctx                 context.Context
	runningTriggersLock sync.Mutex
	runningTriggers     map[string]func()
}

// +kubebuilder:rbac:groups=triggers.harikube.info,resources=httptriggers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=httptriggers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=httptriggers/finalizers,verbs=update

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list

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
	logger := logf.FromContext(ctx).WithValues("name", req.NamespacedName)

	trigger := triggersv1.HTTPTrigger{}
	if err := r.Get(ctx, req.NamespacedName, &trigger); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Failed to fetch TopologyConfig")

		return ctrl.Result{}, err
	}

	r.runningTriggersLock.Lock()
	defer r.runningTriggersLock.Unlock()

	if trigger.DeletionTimestamp != nil || !trigger.DeletionTimestamp.IsZero() {
		logger.Info("HTTPTrigger deleted")

		if cancel, ok := r.runningTriggers[req.String()]; ok {
			cancel()

			delete(r.runningTriggers, req.String())
		}

		return ctrl.Result{}, nil
	} else if trigger.Generation == 1 {
		logger.Info("HTTPTrigger created")
	} else {
		logger.Info("HTTPTrigger updated")
	}

	if err := r.createTrigger(&trigger); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

//nolint:gocyclo
func (r *HTTPTriggerReconciler) createTrigger(trigger *triggersv1.HTTPTrigger) error {
	triggerRefName := trigger.Namespace + "/" + trigger.Name

	if cancel, ok := r.runningTriggers[triggerRefName]; ok {
		cancel()
		delete(r.runningTriggers, triggerRefName)
	}

	listOpts := metav1.ListOptions{
		ResourceVersion:      "0",
		ResourceVersionMatch: metav1.ResourceVersionMatchNotOlderThan,
		TimeoutSeconds:       ptr.To(int64(60)),
		SendInitialEvents:    &trigger.Spec.SendInitialEvents,
		Watch:                true,
		AllowWatchBookmarks:  false,
		LabelSelector:        strings.Join(trigger.Spec.LabelSelector, ","),
		FieldSelector:        strings.Join(trigger.Spec.FieldSelector, ","),
	}

	apiParts := strings.Split(trigger.Spec.Meta.APIVersion, "/")
	if len(apiParts) == 1 {
		apiParts = append(apiParts, apiParts[0])
		apiParts[0] = ""
	}
	gvr := schema.GroupVersionResource{
		Group:    apiParts[0],
		Version:  apiParts[1],
		Resource: inflect.Pluralize(strings.ToLower(trigger.Spec.Meta.Kind)),
	}
	gvk := schema.GroupVersionKind{
		Group:   apiParts[0],
		Version: apiParts[1],
		Kind:    trigger.Spec.Meta.Kind,
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

	var userAuthPassword string
	if trigger.Spec.Endpoint.Auth.BasicAuth != nil {
		passwordSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Endpoint.Auth.BasicAuth.PasswordRef.Name,
		}, &passwordSecret); err != nil {
			return err
		}
		userAuthPassword = string(passwordSecret.Data[trigger.Spec.Endpoint.Auth.BasicAuth.PasswordRef.Key])
	}

	headerSecrets := map[string]string{}
	for k, v := range trigger.Spec.Endpoint.Headers.FromSecretRef {
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
	if trigger.Spec.Endpoint.Body.Signature.KeySecretRef.Name != "" {
		signatureSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Endpoint.Body.Signature.KeySecretRef.Name,
		}, &signatureSecret); err != nil {
			return err
		}
		signature = signatureSecret.Data[trigger.Spec.Endpoint.Body.Signature.KeySecretRef.Key]
	}

	httpTransport := &http.Transport{
		MaxIdleConns:    int(trigger.Spec.Concurrency),
		IdleConnTimeout: time.Minute,
	}
	if trigger.Spec.Endpoint.Auth.TLS != nil {
		caSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Endpoint.Auth.TLS.CARef.Name,
		}, &caSecret); err != nil {
			return err
		}

		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caSecret.Data[trigger.Spec.Endpoint.Auth.TLS.CARef.Key]); !ok {
			return fmt.Errorf("error appending CA cert to pool")
		}

		certSecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Endpoint.Auth.TLS.CertRef.Name,
		}, &certSecret); err != nil {
			return err
		}

		keySecret := corev1.Secret{}
		if err := r.Get(depFetchCtx, types.NamespacedName{
			Namespace: trigger.Namespace,
			Name:      trigger.Spec.Endpoint.Auth.TLS.KeyRef.Name,
		}, &keySecret); err != nil {
			return err
		}

		clientCert, err := tls.X509KeyPair(
			certSecret.Data[trigger.Spec.Endpoint.Auth.TLS.CertRef.Key],
			keySecret.Data[trigger.Spec.Endpoint.Auth.TLS.KeyRef.Key],
		)
		if err != nil {
			return err
		}

		httpTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: trigger.Spec.Endpoint.Auth.TLS.InsecureSkipVerify,
			RootCAs:            caCertPool,
			Certificates:       []tls.Certificate{clientCert},
		}
	}
	httpClient := &http.Client{
		Timeout:   trigger.Spec.Endpoint.Delivery.Timeout.Duration,
		Transport: httpTransport,
	}

	watchClients := []dynamic.ResourceInterface{}
	if len(trigger.Spec.Namespaces) != 0 {
		for _, namespace := range trigger.Spec.Namespaces {
			watchClients = append(watchClients, r.DynamicClient.Resource(gvr).Namespace(namespace))
		}
	} else {
		watchClients = append(watchClients, r.DynamicClient.Resource(gvr))
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

	cases := []reflect.SelectCase{}
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

	handleError := func(err error, logger logr.Logger) {
		r.runningTriggersLock.Lock()
		defer r.runningTriggersLock.Unlock()

		if cancel, ok := r.runningTriggers[triggerRefName]; ok {
			logger.Error(err, "Watcher closed")
			cancel()
			delete(r.runningTriggers, triggerRefName)
		}
	}

	logger := logf.FromContext(ctx).WithValues("trigger", triggerRefName, "grv", gvr.String())
	logger.Info("Watcher started")

	for i := 1; i <= int(trigger.Spec.Concurrency); i++ {
		go func() {
			for {
				chosen, data, ok := reflect.Select(cases)
				if !ok {
					handleError(fmt.Errorf("closed channel"), logger)

					return
				}

				cases[chosen].Chan = reflect.Value{}

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

					continue
				}

				if trigger.Spec.EventFilter != "" {
					old := map[string]interface{}{}
					if md, ok := unstructuredObj.Object["metadata"]; ok {
						if an, ok := md.(map[string]interface{})["annotations"]; ok {
							if lac, ok := an.(map[string]interface{})["kubectl.kubernetes.io/last-applied-configuration"]; ok {
								if err := json.Unmarshal([]byte(lac.(string)), &old); err != nil {
									handleError(err, logger)

									continue
								}
							}
						}
					}

					renderer, err := template.New("filter_template").Parse(fmt.Sprintf("{{if %s}}true{{end}}", trigger.Spec.EventFilter))
					if err != nil {
						handleError(err, logger)

						return
					}

					var renderedMatch bytes.Buffer
					if err = renderer.Execute(&renderedMatch, map[string]any{
						"old": old,
						"new": unstructuredObj.Object,
					}); err != nil {
						handleError(err, logger)

						continue
					}
					if renderedMatch.String() != "true" {
						continue
					}
				}

				var url string
				switch {
				case trigger.Spec.Endpoint.URL.Static != nil:
					url = *trigger.Spec.Endpoint.URL.Static
				case trigger.Spec.Endpoint.URL.Template != nil:
					renderer, err := template.New("url_template").Parse(*trigger.Spec.Endpoint.URL.Template)
					if err != nil {
						handleError(err, logger)

						return
					}

					var renderedURL bytes.Buffer
					if err = renderer.Execute(&renderedURL, unstructuredObj); err != nil {
						handleError(err, logger)

						return
					}
					url = renderedURL.String()
				case trigger.Spec.Endpoint.URL.Service != nil:
					var uri string
					switch {
					case trigger.Spec.Endpoint.URL.Service.URI.Static != nil:
						uri = *trigger.Spec.Endpoint.URL.Service.URI.Static
					case trigger.Spec.Endpoint.URL.Service.URI.Template != nil:
						renderer, err := template.New("uri_template").Parse(*trigger.Spec.Endpoint.URL.Service.URI.Template)
						if err != nil {
							handleError(err, logger)

							return
						}

						var renderedURI bytes.Buffer
						if err = renderer.Execute(&renderedURI, unstructuredObj); err != nil {
							handleError(err, logger)

							return
						}
					default:
						handleError(fmt.Errorf("missing URI generation strategy"), logger)

						return
					}

					url = fmt.Sprintf("http://%s/%s/%s",
						trigger.Spec.Endpoint.URL.Service.Name,
						trigger.Spec.Endpoint.URL.Service.Namespace,
						strings.TrimPrefix(uri, "/"),
					)
				default:
					// TODO Ingress, gateway
					handleError(fmt.Errorf("missing URL generation strategy"), logger)

					return
				}

				body := ""
				if trigger.Spec.Endpoint.Body.Template != "" {
					renderer, err := template.New("body_template_").Parse(trigger.Spec.Endpoint.Body.Template)
					if err != nil {
						handleError(err, logger)

						return
					}

					var renderedBody bytes.Buffer
					if err = renderer.Execute(&renderedBody, unstructuredObj); err != nil {
						handleError(err, logger)

						return
					}
					body = renderedBody.String()
				}

				headers := map[string]string{
					"Content-Type": trigger.Spec.Endpoint.Body.ContentType,
				}
				maps.Copy(headers, trigger.Spec.Endpoint.Headers.Static)
				for k, v := range trigger.Spec.Endpoint.Headers.Template {
					renderer, err := template.New("header_template_" + k).Parse(v)
					if err != nil {
						handleError(err, logger)

						return
					}

					var renderedHeader bytes.Buffer
					if err = renderer.Execute(&renderedHeader, unstructuredObj); err != nil {
						handleError(err, logger)

						return
					}
					headers[k] = renderedHeader.String()
				}
				for k := range trigger.Spec.Endpoint.Headers.FromSecretRef {
					headers[k] = headerSecrets[k]
				}

				switch {
				case trigger.Spec.Endpoint.Body.Signature.HMAC != nil:
					var hash func() hash.Hash
					switch trigger.Spec.Endpoint.Body.Signature.HMAC.HashType {
					case triggersv1.SignatureHashTypeSHA256:
						hash = sha256.New
					case triggersv1.SignatureHashTypeSHA512:
						hash = sha512.New
					}

					hasher := hmac.New(hash, signature)
					hasher.Write([]byte(body))
					signatureBytes := hasher.Sum(nil)

					headers[trigger.Spec.Endpoint.Body.Signature.Header] = hex.EncodeToString(signatureBytes)
				}

				var retryErr error
				for i := 0; i <= int(trigger.Spec.Endpoint.Delivery.Retries); i++ {
					reqCtx, reqCancel := context.WithTimeout(ctx, trigger.Spec.Endpoint.Delivery.Timeout.Duration)

					req, err := http.NewRequestWithContext(reqCtx, string(trigger.Spec.Endpoint.Method), url, strings.NewReader(body))
					if err != nil {
						handleError(err, logger)
						reqCancel()

						return
					}

					if trigger.Spec.Endpoint.Auth.BasicAuth != nil {
						req.SetBasicAuth(trigger.Spec.Endpoint.Auth.BasicAuth.User, userAuthPassword)
					}

					for k, v := range headers {
						req.Header.Add(k, v)
					}

					resp, err := httpClient.Do(req)
					if err != nil {
						retryErr = err

						reqCancel()

						<-time.After(time.Second)

						continue
					}

					reqCancel()
					if err := resp.Body.Close(); err != nil {
						handleError(err, logger)

						return
					}

					break
				}

				if retryErr != nil {
					handleError(retryErr, logger)
				}
			}
		}()
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *HTTPTriggerReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	r.ctx = ctx
	r.runningTriggersLock = sync.Mutex{}
	r.runningTriggers = map[string]func(){}

	existingTriggers := triggersv1.HTTPTriggerList{}
	if err := mgr.GetClient().List(ctx, &existingTriggers); err != nil {
		return err
	}

	for _, trigger := range existingTriggers.Items {
		if err := r.createTrigger(&trigger); err != nil {
			for _, tc := range r.runningTriggers {
				tc()
			}

			return err
		}
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(r.For).
		Named(r.Name).
		WithOptions(controller.Options{
			NeedLeaderElection:      ptr.To(true),
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
			Logger:                  mgr.GetLogger(),
		}).
		Complete(r)
}
