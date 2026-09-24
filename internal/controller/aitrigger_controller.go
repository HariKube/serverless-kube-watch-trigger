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
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/facette/natsort"
	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
)

type aiChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type aiChatCompletionRequest struct {
	Model       string          `json:"model"`
	Messages    []aiChatMessage `json:"messages"`
	Temperature *float64        `json:"temperature,omitempty"`
	MaxTokens   *int32          `json:"max_tokens,omitempty"`
}

// AITriggerReconciler reconciles a AITrigger object
type AITriggerReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	DynamicClient *dynamic.DynamicClient
	Recorder      record.EventRecorder

	ctx                 context.Context
	runningTriggersLock sync.Mutex
	runningTriggers     map[string]func()

	triggerLocksLock sync.Mutex
	triggerLocks     map[string]*sync.Mutex
}

// triggerLock returns the mutex that serializes reconcile work (session
// creation, update and deletion) for a single trigger so a trigger can never
// end up with more than one live watcher session. Reconciles for different
// triggers hold different locks and therefore run in parallel instead of
// serializing on the shared runningTriggersLock.
func (r *AITriggerReconciler) triggerLock(triggerRefName string) *sync.Mutex {
	r.triggerLocksLock.Lock()
	defer r.triggerLocksLock.Unlock()

	if mu, ok := r.triggerLocks[triggerRefName]; ok {
		return mu
	}

	mu := &sync.Mutex{}
	r.triggerLocks[triggerRefName] = mu

	return mu
}

// stopRunningTrigger cancels and removes the watcher session for a trigger.
// runningTriggersLock must NOT be held by the caller.
func (r *AITriggerReconciler) stopRunningTrigger(triggerRefName string) {
	r.runningTriggersLock.Lock()
	defer r.runningTriggersLock.Unlock()

	r.stopRunningTriggerLocked(triggerRefName)
}

// stopRunningTriggerLocked is stopRunningTrigger with runningTriggersLock held.
func (r *AITriggerReconciler) stopRunningTriggerLocked(triggerRefName string) {
	if cancel, ok := r.runningTriggers[triggerRefName]; ok {
		cancel()
		delete(r.runningTriggers, triggerRefName)
	}
}

// +kubebuilder:rbac:groups=triggers.harikube.info,resources=aitriggers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=aitriggers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=aitriggers/finalizers,verbs=update

// +kubebuilder:rbac:groups="",resources=secrets;services,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the AITrigger object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *AITriggerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx).WithValues("controller", "aitrigger", "name", req.NamespacedName)

	// Serialize reconcile work per trigger (never globally) so a trigger's
	// watcher session is created/updated/deleted atomically while triggers
	// reconcile against each other in parallel.
	triggerMu := r.triggerLock(req.String())
	triggerMu.Lock()
	defer triggerMu.Unlock()

	trigger := triggersv1.AITrigger{}
	if err := r.Get(ctx, req.NamespacedName, &trigger); err != nil {
		if apierrors.IsNotFound(err) {
			// The trigger was deleted without a finalizer and is already gone.
			// Make sure its watcher session is cancelled and the map entry is
			// removed so it cannot keep delivering events as a zombie.
			r.stopRunningTrigger(req.String())

			return ctrl.Result{}, nil
		}

		logger.Error(err, "Trigger fetch failed")

		return ctrl.Result{}, err
	}

	if trigger.DeletionTimestamp != nil || !trigger.DeletionTimestamp.IsZero() {
		logger.Info("Trigger deleted")

		r.stopRunningTrigger(req.String())

		return ctrl.Result{}, nil
	} else if trigger.Generation == 1 && trigger.Status.LastGeneration == 0 {
		logger.Info("Trigger created")
	} else {
		if trigger.Status.Phase == triggersv1.TriggerPhaseRunning && trigger.Status.LastGeneration == trigger.Generation {
			return ctrl.Result{}, nil
		}

		logger.Info("Trigger updated")
	}

	r.stopRunningTrigger(req.String())

	recoveryRestart := !trigger.Status.ErrorTime.IsZero() &&
		trigger.Status.LastGeneration == trigger.Generation

	patchedTrigger := trigger.DeepCopy()
	patchedTrigger.Status.LastGeneration = trigger.Generation

	if err := r.createTrigger(req.String(), &trigger); err != nil {
		permanent := errors.Is(err, ErrInvalidTriggerContent)
		if !permanent {
			logger.Error(err, "Trigger initialization failed")
		}

		patchedTrigger.Status.Phase = triggersv1.TriggerPhaseError
		patchedTrigger.Status.ErrorTime = metav1.Now()
		patchedTrigger.Status.ErrorReason = err.Error()
		patchedTrigger.Status.ErrorResourceVersion = "0"

		if err := r.Status().Patch(ctx, patchedTrigger, client.MergeFrom(&trigger)); err != nil {
			if apierrors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}

			logger.Error(err, "Trigger status update failed")

			return ctrl.Result{}, err
		}

		if permanent {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	patchedTrigger.Status.Phase = triggersv1.TriggerPhaseRunning
	if !recoveryRestart {
		patchedTrigger.Status.ErrorTime = metav1.Time{}
		patchedTrigger.Status.ErrorReason = ""
		patchedTrigger.Status.ErrorResourceVersion = "0"
	}

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
func (r *AITriggerReconciler) createTrigger(triggerRefName string, trigger *triggersv1.AITrigger) error {
	resourceVersion := triggerResourceVersion(trigger.Status.ErrorResourceVersion)
	gvr, gvk := buildTriggerResourceInfo(trigger.Spec.Resource)
	eventTypes := buildTriggerEventTypes(trigger.Spec.EventType)

	compiledTemplates := map[string]*template.Template{}
	if err := compileSharedTemplates(compiledTemplates, trigger.Spec.EventFilter, trigger.Spec.URL, trigger.Spec.Headers); err != nil {
		return err
	}
	var temperature *float64
	if trigger.Spec.Request.Temperature != nil {
		parsedTemperature, err := strconv.ParseFloat(*trigger.Spec.Request.Temperature, 64)
		if err != nil {
			return errors.Join(err, ErrInvalidTriggerContent, errors.New("failed to parse temperature"))
		}
		temperature = &parsedTemperature
	}

	requestTemplateFuncs := template.FuncMap{
		"toJson": toJson,
	}
	if trigger.Spec.Request.SystemPrompt != "" {
		if err := addCompiledTemplate(compiledTemplates, "system_prompt_template", trigger.Spec.Request.SystemPrompt, requestTemplateFuncs); err != nil {
			return errors.Join(err, ErrInvalidTriggerContent, errors.New("failed to parse system prompt template"))
		}
	}
	if trigger.Spec.Request.PromptTemplate != "" {
		if err := addCompiledTemplate(compiledTemplates, "prompt_template", trigger.Spec.Request.PromptTemplate, requestTemplateFuncs); err != nil {
			return errors.Join(err, ErrInvalidTriggerContent, errors.New("failed to parse prompt template"))
		}
	}

	depFetchCtx, depFetchCancel := context.WithTimeout(r.ctx, time.Minute)
	defer depFetchCancel()

	serviceScheme, servicePort, err := resolveServiceEndpoint(depFetchCtx, r, trigger.Spec.URL.Service)
	if err != nil {
		return err
	}

	var userAuthPassword string
	if trigger.Spec.Auth.BasicAuth != nil {
		userAuthPassword, err = loadSecretString(depFetchCtx, r, trigger.Namespace, trigger.Spec.Auth.BasicAuth.PasswordRef)
		if err != nil {
			return err
		}
	}

	headerSecrets, err := loadHeaderSecrets(depFetchCtx, r, trigger.Namespace, trigger.Spec.Headers.FromSecretRef)
	if err != nil {
		return err
	}

	concurrency := normalizeConcurrency(trigger.Spec.Concurrency)
	httpClient, err := newTriggerHTTPClient(depFetchCtx, r, trigger.Namespace, trigger.Spec.Auth.TLS, trigger.Spec.Delivery.Timeout.Duration, concurrency)
	if err != nil {
		return err
	}

	resourceClient := r.DynamicClient.Resource(gvr)
	watchClients := buildWatchClients(resourceClient, trigger.Spec.Namespaces)

	ctx, cancel := context.WithCancel(r.ctx)

	r.runningTriggersLock.Lock()
	r.runningTriggers[triggerRefName] = cancel
	r.runningTriggersLock.Unlock()

	listOpts := buildWatcherListOptions(resourceVersion, trigger.Spec.SendInitialEvents, trigger.Spec.LabelSelector, trigger.Spec.FieldSelector)

	watchers, err := openWatchers(ctx, watchClients, listOpts)
	if err != nil {
		r.stopRunningTrigger(triggerRefName)

		return err
	}

	lastResourceVersion := atomic.Pointer[string]{}
	lastResourceVersion.Store(ptr.To("0"))

	var (
		watchersMu      sync.Mutex
		sessionGen      uint64
		sessionWatchers []watch.Interface
	)
	sessionWatchers = watchers

	// resumeListOptions builds the options used to transparently re-open the
	// watch stream after the server closes it (see TimeoutSeconds in
	// buildWatcherListOptions), resuming from the last seen resourceVersion.
	resumeListOptions := func() metav1.ListOptions {
		return buildWatcherListOptions(*lastResourceVersion.Load(), false, trigger.Spec.LabelSelector, trigger.Spec.FieldSelector)
	}

	reconnect := func(expectedGen uint64) error {
		reopened, err := openWatchers(ctx, watchClients, resumeListOptions())
		if err != nil {
			return err
		}

		watchersMu.Lock()
		defer watchersMu.Unlock()

		if sessionGen != expectedGen {
			stopWatchers(reopened)

			return nil // another worker already reconnected
		}

		sessionWatchers = reopened
		sessionGen++

		return nil
	}

	handleError := func(err error, logger logr.Logger) {
		handleTriggerWatcherError(
			r.ctx,
			err,
			logger,
			r.Recorder,
			trigger,
			triggerRefName,
			*lastResourceVersion.Load(),
			&r.runningTriggersLock,
			r.runningTriggers,
			ctx.Done(),
			func() {
				watchersMu.Lock()
				active := sessionWatchers
				watchersMu.Unlock()

				stopWatchers(active)
			},
			func(patchCtx context.Context, errorTime metav1.Time, errorReason, errorResourceVersion string) (bool, error) {
				latest := &triggersv1.AITrigger{}
				if err := r.Get(patchCtx, client.ObjectKeyFromObject(trigger), latest); err != nil {
					return false, err
				}

				if latest.Generation != trigger.Generation || latest.Status.Phase == triggersv1.TriggerPhaseError {
					return false, nil
				}

				patched := latest.DeepCopy()
				patched.Status.Phase = triggersv1.TriggerPhaseError
				patched.Status.ErrorTime = errorTime
				patched.Status.ErrorReason = errorReason
				patched.Status.ErrorResourceVersion = errorResourceVersion

				return true, r.Status().Patch(patchCtx, patched, client.MergeFrom(latest))
			},
		)
	}

	logger := logf.FromContext(ctx).WithValues("trigger", triggerRefName, "grv", gvr.String())
	logger.Info("Watcher started")

	const (
		minReconnectBackoff = time.Second
		maxReconnectBackoff = 30 * time.Second
	)

	for i := 1; i <= int(concurrency); i++ {
		go func() {
			reconnectBackoff := minReconnectBackoff

			for {
				watchersMu.Lock()
				activeWatchers := sessionWatchers
				activeGen := sessionGen
				watchersMu.Unlock()

				_, data, ok := reflect.Select(buildWatcherSelectCases(activeWatchers, ctx.Done()))
				if !ok {
					stopWatchers(activeWatchers)

					if ctx.Err() != nil {
						return
					}

					logger.V(1).Info("Watch stream closed, reconnecting", "gen", activeGen, "lastResourceVersion", *lastResourceVersion.Load())

					if err := reconnect(activeGen); err != nil {
						logger.Error(err, "Reconnect failed", "gen", activeGen)
						handleError(err, logger)

						return
					}

					logger.V(1).Info("Watch stream reconnected", "gen", activeGen)

					<-time.After(reconnectBackoff)

					if reconnectBackoff < maxReconnectBackoff {
						reconnectBackoff *= 2
					}

					continue
				}

				reconnectBackoff = minReconnectBackoff

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

				if event.Type == watch.Bookmark {
					bookmark, ok := event.Object.(*metav1.PartialObjectMetadata)
					if !ok {
						logger.Error(errors.New("failed to convert bookmark to metav1.PartialObjectMetadata"), "event", event)

						continue
					} else if bookmark == nil {
						continue
					}

					logger.Info("Received bookmark event", "resourceVersion", bookmark.GetResourceVersion())

					for {
						rv := bookmark.GetResourceVersion()
						lrv := lastResourceVersion.Load()

						if natsort.Compare(rv, *lrv) {
							break
						} else if lastResourceVersion.CompareAndSwap(lrv, &rv) {
							break
						}
					}

					continue
				}

				if trigger.Spec.EventFilter != "" {
					renderedMatch, err := renderTemplateToString(compiledTemplates, filterTemplateName, unstructuredObj.Object)
					if err != nil {
						handleError(err, logger)

						return
					}
					if renderedMatch != trueString {
						continue
					}
				}

				url, err := buildTriggerURL(trigger.Spec.URL, compiledTemplates, unstructuredObj.Object, serviceScheme, servicePort)
				if err != nil {
					handleError(err, logger)

					return
				}

				systemPrompt := ""
				if trigger.Spec.Request.SystemPrompt != "" {
					systemPrompt, err = renderTemplateToString(compiledTemplates, "system_prompt_template", unstructuredObj.Object)
					if err != nil {
						handleError(err, logger)

						return
					}
				}

				renderedPrompt, err := renderTemplateToString(compiledTemplates, "prompt_template", unstructuredObj.Object)
				if err != nil {
					handleError(err, logger)

					return
				}

				payload := aiChatCompletionRequest{
					Model: trigger.Spec.Request.Model,
					Messages: []aiChatMessage{{
						Role:    "user",
						Content: renderedPrompt,
					}},
					Temperature: temperature,
					MaxTokens:   trigger.Spec.Request.MaxTokens,
				}
				if systemPrompt != "" {
					payload.Messages = append([]aiChatMessage{{
						Role:    "system",
						Content: systemPrompt,
					}}, payload.Messages...)
				}

				payloadBytes, err := json.Marshal(payload)
				if err != nil {
					handleError(err, logger)

					return
				}
				body := string(payloadBytes)

				headers, err := buildTriggerHeaders("application/json", trigger.Spec.Headers, headerSecrets, compiledTemplates, unstructuredObj.Object)
				if err != nil {
					handleError(err, logger)

					return
				}

				method := methodOrDefault(trigger.Spec.Method)

				var retryErr error
				for i := 0; i <= int(trigger.Spec.Delivery.Retries); i++ {
					reqCtx, reqCancel := context.WithTimeout(ctx, normalizeHTTPTimeout(trigger.Spec.Delivery.Timeout.Duration))

					req, err := http.NewRequestWithContext(reqCtx, method, url, strings.NewReader(body))
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
						if err := resp.Body.Close(); err != nil {
							handleError(err, logger)

							return
						}

						<-time.After(time.Second)

						continue
					}

					logger.Info("Endpoint successfully called", "name", metadata["name"], "namespace", metadata["namespace"], "resourceVersion", metadata["resourceVersion"], "eventType", event.Type)

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
					metadata := unstructuredObj.Object["metadata"].(map[string]interface{})
					emitTriggerCallFailureEvent(r.Recorder, trigger, triggerRefName, methodOrDefault(trigger.Spec.Method), url, event.Type, metadata, retryErr)
					handleError(fmt.Errorf("retry failed: %w", retryErr), logger)

					return
				}
			}
		}()
	}

	return nil
}

func (r *AITriggerReconciler) WatchInit(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	existingTriggers := triggersv1.AITriggerList{}
	if err := r.List(ctx, &existingTriggers); err != nil {
		return err
	}

	for _, trigger := range existingTriggers.Items {
		refName := trigger.Namespace + "/" + trigger.Name

		triggerMu := r.triggerLock(refName)
		triggerMu.Lock()
		initErr := r.createTrigger(refName, &trigger)
		triggerMu.Unlock()

		if initErr != nil {
			// Cancel every session started so far: a partially-initialized
			// operator must not leave zombie watchers behind.
			r.runningTriggersLock.Lock()
			for runningRef := range r.runningTriggers {
				if cancelFn, ok := r.runningTriggers[runningRef]; ok {
					cancelFn()
					delete(r.runningTriggers, runningRef)
				}
			}
			r.runningTriggersLock.Unlock()

			return initErr
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AITriggerReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager, maxConcurrentReconciles int, wg *sync.WaitGroup) error {
	r.ctx = ctx
	r.Recorder = mgr.GetEventRecorderFor("aitrigger-controller")
	r.runningTriggersLock = sync.Mutex{}
	r.runningTriggers = map[string]func(){}
	r.triggerLocksLock = sync.Mutex{}
	r.triggerLocks = map[string]*sync.Mutex{}

	wg.Add(1)
	go func() {
		defer wg.Done()

		<-ctx.Done()

		// Cancel every running watcher session and remove its map entry so the
		// goroutines watching it can terminate promptly.
		r.runningTriggersLock.Lock()
		for refName := range r.runningTriggers {
			r.stopRunningTriggerLocked(refName)
		}
		r.runningTriggersLock.Unlock()

		// Wait for the sessions to drain so in-flight status writes and watch
		// loops settle before the manager stops. The wait is bounded so
		// shutdown never hangs even if a session is stuck.
		drainStart := time.Now()
		for {
			r.runningTriggersLock.Lock()
			running := len(r.runningTriggers)
			r.runningTriggersLock.Unlock()

			if running == 0 {
				return
			}

			if time.Since(drainStart) >= 30*time.Second {
				r.runningTriggersLock.Lock()
				r.runningTriggers = map[string]func(){}
				r.runningTriggersLock.Unlock()

				return
			}

			time.Sleep(50 * time.Millisecond)
		}
	}()

	return ctrl.NewControllerManagedBy(mgr).
		For(&triggersv1.AITrigger{}).
		Named("aitrigger").
		WithOptions(controller.Options{
			NeedLeaderElection:      ptr.To(true),
			MaxConcurrentReconciles: maxConcurrentReconciles,
			RecoverPanic:            ptr.To(true),
			Logger:                  mgr.GetLogger(),
		}).
		Complete(r)
}
