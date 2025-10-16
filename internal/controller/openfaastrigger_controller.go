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
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/go-openapi/inflect"
	"github.com/tidwall/gjson"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	triggersv1 "github.com/mhmxs/serverless-kube-watch-trigger/api/v1"
)

// OpenFaaSTriggerReconciler reconciles a OpenFaaSTrigger object
type OpenFaaSTriggerReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	DynamicClient *dynamic.DynamicClient

	ctx                 context.Context
	runningTriggersLock sync.Mutex
	runningTriggers     map[string]func()
}

// +kubebuilder:rbac:groups=triggers.harikube.info,resources=openfaastriggers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=openfaastriggers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=openfaastriggers/finalizers,verbs=update

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the OpenFaaSTrigger object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *OpenFaaSTriggerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx).WithValues("name", req.NamespacedName)

	trigger := triggersv1.OpenFaaSTrigger{}
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
		logger.Info("OpenFaaSTrigger deleted")

		if cancel, ok := r.runningTriggers[req.NamespacedName.String()]; ok {
			cancel()

			delete(r.runningTriggers, req.NamespacedName.String())
		}

		return ctrl.Result{}, nil
	} else if trigger.Generation == 1 {
		logger.Info("OpenFaaSTrigger created")
	} else {
		logger.Info("OpenFaaSTrigger updated")
	}

	if err := r.createTrigger(&trigger); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *OpenFaaSTriggerReconciler) createTrigger(trigger *triggersv1.OpenFaaSTrigger) error {
	triggerRefName := trigger.Namespace + "/" + trigger.Name

	if cancel, ok := r.runningTriggers[triggerRefName]; ok {
		cancel()

		delete(r.runningTriggers, triggerRefName)
	}

	ctx, cancel := context.WithCancel(r.ctx)

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
		apiParts = append(apiParts, "v1")
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

	clients := []dynamic.ResourceInterface{}
	if len(trigger.Spec.Namespaces) != 0 {
		for _, namespace := range trigger.Spec.Namespaces {
			clients = append(clients, r.DynamicClient.Resource(gvr).Namespace(namespace))
		}
	} else {
		clients = append(clients, r.DynamicClient.Resource(gvr))
	}

	closeChan := make(chan bool, len(clients))
	closeChanClose := sync.Once{}

	watchers := []watch.Interface{}
	for _, client := range clients {
		watcher, err := client.Watch(ctx, listOpts)
		if err != nil {
			for _, watcher := range watchers {
				watcher.Stop()
			}

			return err
		}

		watchers = append(watchers, watcher)
	}

	cases := make([]reflect.SelectCase, len(watchers)+2)
	for i, w := range watchers {
		cases[i] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(w.ResultChan()),
		}
	}
	cases = append(cases, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(r.ctx.Done()),
	}, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(closeChan),
	})

	logger := logf.FromContext(ctx).WithValues("trigger", triggerRefName)

	logger.Info("Watcher started")

	for i := 1; i <= int(trigger.Spec.Concurrency); i++ {
		go func() {
			for {
				for i := 0; i < len(watchers); i++ {
					chosen, data, ok := reflect.Select(cases)
					if !ok {
						closeChanClose.Do(func() {
							logger.Info("Watcher closed")
							close(closeChan)
						})

						return
					}

					cases[chosen].Chan = reflect.Value{}

					eventVal := data.Interface()
					event := eventVal.(watch.Event)

					if event.Type == watch.Error {
						closeChanClose.Do(func() {
							logger.Info("Watcher error")
							close(closeChan)
						})

						return
					} else if event.Type == watch.Bookmark {
						continue
					} else if event.Object == nil {
						continue
					}

					event.Object.GetObjectKind().SetGroupVersionKind(gvk)

					unstructuredObj, ok := event.Object.(*unstructured.Unstructured)
					if !ok {
						closeChanClose.Do(func() {
							logger.Info("Watcher conversion error")
							close(closeChan)
						})

						return
					}

					json, err := json.MarshalIndent(unstructuredObj.Object, "", "  ")
					if err != nil {
						closeChanClose.Do(func() {
							logger.Info("Watcher marshal error")
							close(closeChan)
						})

						return
					}

					result := gjson.GetBytes(json, ".metadata.name")
					logger.Info("Watcher received", "name", result.String())
				}
			}
		}()
	}

	r.runningTriggers[triggerRefName] = cancel

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OpenFaaSTriggerReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	r.ctx = ctx
	r.runningTriggersLock = sync.Mutex{}
	r.runningTriggers = map[string]func(){}

	existingTriggers := triggersv1.OpenFaaSTriggerList{}
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
		For(&triggersv1.OpenFaaSTrigger{}).
		Named("openfaastrigger").
		WithOptions(controller.Options{
			NeedLeaderElection:      ptr.To(true),
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
			Logger:                  mgr.GetLogger(),
		}).
		Complete(r)
}
