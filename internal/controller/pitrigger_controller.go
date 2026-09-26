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
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"

	"github.com/facette/natsort"
	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
	"github.com/harikube/serverless-kube-watch-trigger/pkg/lease"
	"github.com/harikube/serverless-kube-watch-trigger/pkg/partition"
	triggerwatcher "github.com/harikube/serverless-kube-watch-trigger/pkg/watcher"
)

const (
	piTriggerManagedLabel              = "triggers.harikube.info/pitrigger-job"
	piTriggerTriggerNameLabel          = "triggers.harikube.info/pitrigger-name"
	piTriggerInputConfigMapAnnotation  = "triggers.harikube.info/input-configmap"
	piTriggerEventTypeAnnotation       = "triggers.harikube.info/event-type"
	piTriggerResourceVersionAnnotation = "triggers.harikube.info/resource-version"
	piTriggerWorkerContainerName       = "pi-agent"
	piTriggerInputVolumeName           = "pi-trigger-input"
	piTriggerAgentSecretVolumeName     = "pi-agent-config"
	piTriggerPromptsVolumeName         = "pi-agent-prompts"
	piTriggerSkillsVolumeName          = "pi-agent-skills"
	piTriggerInputMountPath            = "/var/run/pi-trigger"
	piTriggerEventFilePath             = piTriggerInputMountPath + "/event.json"
	piTriggerMetadataFilePath          = piTriggerInputMountPath + "/metadata.json"
	piTriggerWorkerHomeDir             = "/tmp/pi-home"
	piTriggerAgentConfigMountPath      = piTriggerWorkerHomeDir + "/.pi/agent"
	piTriggerAgentPromptsMountPath     = piTriggerAgentConfigMountPath + "/prompts"
	piTriggerAgentSkillsMountPath      = piTriggerAgentConfigMountPath + "/skills"
)

type piTriggerEventInput struct {
	TriggerRefName    string                 `json:"triggerRefName"`
	TriggerName       string                 `json:"triggerName"`
	TriggerNamespace  string                 `json:"triggerNamespace"`
	EventType         string                 `json:"eventType"`
	ResourceVersion   string                 `json:"resourceVersion"`
	Message           string                 `json:"message,omitempty"`
	TimedOutLeaseName string                 `json:"timedOutLeaseName,omitempty"`
	Object            map[string]interface{} `json:"object"`
}

type piTriggerJobMetadata struct {
	TriggerRefName    string `json:"triggerRefName"`
	TriggerName       string `json:"triggerName"`
	TriggerNamespace  string `json:"triggerNamespace"`
	EventType         string `json:"eventType"`
	ResourceVersion   string `json:"resourceVersion"`
	Message           string `json:"message,omitempty"`
	TimedOutLeaseName string `json:"timedOutLeaseName,omitempty"`
}

// PiTriggerReconciler reconciles a PiTrigger object.
type PiTriggerReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	DynamicClient *dynamic.DynamicClient
	Recorder      record.EventRecorder

	PartitionController *partition.Controller
	DeletionWatcher     *triggerwatcher.GlobalDeletionWatcher

	ctx                 context.Context
	runningTriggersLock sync.Mutex
	runningTriggers     map[string]func()

	triggerLocksLock sync.Mutex
	triggerLocks     map[string]*sync.Mutex

	deliveryGateRegistry
}

func (r *PiTriggerReconciler) triggerLock(triggerRefName string) *sync.Mutex {
	r.triggerLocksLock.Lock()
	defer r.triggerLocksLock.Unlock()

	if mu, ok := r.triggerLocks[triggerRefName]; ok {
		return mu
	}

	mu := &sync.Mutex{}
	r.triggerLocks[triggerRefName] = mu

	return mu
}

func (r *PiTriggerReconciler) stopRunningTrigger(triggerRefName string) {
	r.runningTriggersLock.Lock()
	defer r.runningTriggersLock.Unlock()

	r.stopRunningTriggerLocked(triggerRefName)
}

func (r *PiTriggerReconciler) stopRunningTriggerLocked(triggerRefName string) {
	if cancel, ok := r.runningTriggers[triggerRefName]; ok {
		cancel()
		delete(r.runningTriggers, triggerRefName)
		recordControllerSessionStop(metricControllerPiTrigger)
	}
	if r.DeletionWatcher != nil {
		r.DeletionWatcher.UnregisterTask(triggerRefName)
	}
}

// +kubebuilder:rbac:groups=triggers.harikube.info,resources=pitriggers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=pitriggers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=pitriggers/finalizers,verbs=update
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=create;delete;get;list;watch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=create;delete;get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch;update

func (r *PiTriggerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	recordReconcileStart(metricControllerPiTrigger)
	defer recordReconcileDone(metricControllerPiTrigger)

	logger := logf.FromContext(ctx).WithValues("controller", "pitrigger", "name", req.NamespacedName)
	triggerRefName := req.String()

	triggerMu := r.triggerLock(triggerRefName)
	triggerMu.Lock()
	defer triggerMu.Unlock()

	trigger := triggersv1.PiTrigger{}
	if err := r.Get(ctx, req.NamespacedName, &trigger); err != nil {
		if apierrors.IsNotFound(err) {
			r.stopRunningTrigger(triggerRefName)
			r.remove(triggerRefName)
			sharedPiTriggerJobCounterRegistry.remove(triggerRefName)
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Trigger fetch failed")
		return ctrl.Result{}, err
	}

	if result, done, err := r.preflightReconcile(ctx, logger, triggerRefName, &trigger); done || err != nil {
		return result, err
	}

	leaseAcquired, result, err := r.acquireReconcileLease(ctx, logger, &trigger)
	if err != nil || result != nil {
		if result == nil {
			return ctrl.Result{}, err
		}
		return *result, err
	}

	taskSucceeded := false
	if leaseAcquired {
		defer func() {
			if !taskSucceeded {
				return
			}
			if err := lease.ClearLease(ctx, r.Client, &trigger); err != nil {
				logger.Error(err, "Trigger annotation lease release failed", "annotation", lease.AnnotationKey)
			}
		}()
	}

	r.stopRunningTrigger(triggerRefName)

	recoveryRestart := !trigger.Status.ErrorTime.IsZero() && trigger.Status.LastGeneration == trigger.Generation
	patchedTrigger := trigger.DeepCopy()
	patchedTrigger.Status.LastGeneration = trigger.Generation

	if err := r.createTrigger(triggerRefName, &trigger); err != nil {
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

	taskSucceeded = true
	return ctrl.Result{}, nil
}

func (r *PiTriggerReconciler) preflightReconcile(ctx context.Context, logger logr.Logger, triggerRefName string, trigger *triggersv1.PiTrigger) (ctrl.Result, bool, error) {
	if trigger.DeletionTimestamp != nil || !trigger.DeletionTimestamp.IsZero() {
		logger.Info("Trigger deleted")
		if err := r.dispatchOwnerLeaseTimeoutJob(ctx, triggerRefName, trigger); err != nil {
			logger.Error(err, "Trigger deletion timeout job dispatch failed")
		}
		r.stopRunningTrigger(triggerRefName)
		r.remove(triggerRefName)
		sharedPiTriggerJobCounterRegistry.remove(triggerRefName)
		return ctrl.Result{}, true, nil
	}
	if r.PartitionController != nil && !r.PartitionController.OwnsObject(trigger) {
		r.stopRunningTrigger(triggerRefName)
		r.remove(triggerRefName)
		sharedPiTriggerJobCounterRegistry.remove(triggerRefName)
		return ctrl.Result{}, true, nil
	}
	if trigger.Generation == 1 && trigger.Status.LastGeneration == 0 {
		logger.Info("Trigger created")
		return ctrl.Result{}, false, nil
	}
	if trigger.Status.Phase == triggersv1.TriggerPhaseRunning && trigger.Status.LastGeneration == trigger.Generation {
		result, err := r.handleRunningTriggerLease(ctx, logger, trigger)
		return result, true, err
	}

	logger.Info("Trigger updated")
	return ctrl.Result{}, false, nil
}

func (r *PiTriggerReconciler) handleRunningTriggerLease(ctx context.Context, logger logr.Logger, trigger *triggersv1.PiTrigger) (ctrl.Result, error) {
	lockDuration := trigger.Spec.LockDuration.Duration
	if lockDuration <= 0 {
		return ctrl.Result{}, nil
	}
	if requeueAfter := lease.ActiveLeaseRemaining(trigger, time.Now().UTC(), lockDuration); requeueAfter > 0 {
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}
	if _, ok := trigger.GetAnnotations()[lease.AnnotationKey]; !ok {
		return ctrl.Result{}, nil
	}
	if err := lease.ClearLease(ctx, r.Client, trigger); err != nil {
		logger.Error(err, "Trigger annotation lease release failed", "annotation", lease.AnnotationKey)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *PiTriggerReconciler) acquireReconcileLease(ctx context.Context, logger logr.Logger, trigger *triggersv1.PiTrigger) (bool, *ctrl.Result, error) {
	lockDuration := trigger.Spec.LockDuration.Duration
	if lockDuration <= 0 {
		return false, nil, nil
	}

	leaseResult, err := lease.TryAcquireLease(ctx, r.Client, trigger, time.Now().UTC(), lockDuration)
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

//nolint:gocyclo
func (r *PiTriggerReconciler) createTrigger(triggerRefName string, trigger *triggersv1.PiTrigger) error {
	resourceVersion := triggerResourceVersion(trigger.Status.ErrorResourceVersion)
	if trigger.ResourceVersion != "" && natsort.Compare(resourceVersion, trigger.ResourceVersion) {
		resourceVersion = trigger.ResourceVersion
	}
	if latestJobResourceVersion, err := r.latestDispatchedResourceVersion(r.ctx, trigger); err != nil {
		return err
	} else if latestJobResourceVersion != "" && natsort.Compare(resourceVersion, latestJobResourceVersion) {
		resourceVersion = latestJobResourceVersion
	}
	gvr, gvk := buildTriggerResourceInfo(trigger.Spec.Resource)
	eventTypes := buildTriggerEventTypes(trigger.Spec.EventType)

	compiledTemplates := map[string]*template.Template{}
	if trigger.Spec.EventFilter != "" {
		if err := addCompiledTemplate(compiledTemplates, filterTemplateName, fmt.Sprintf("{{if %s}}true{{end}}", trigger.Spec.EventFilter), nil); err != nil {
			return errors.Join(err, ErrInvalidTriggerContent, errors.New("failed to parse filter template"))
		}
	}

	depFetchCtx, depFetchCancel := context.WithTimeout(r.ctx, time.Minute)
	defer depFetchCancel()

	if err := validatePiAgentConfigRefs(depFetchCtx, r, trigger.Namespace, trigger.Spec.Agent); err != nil {
		return err
	}

	concurrency := normalizeConcurrency(trigger.Spec.Concurrency)
	resourceClient := r.DynamicClient.Resource(gvr)
	watchClients := buildWatchClients(resourceClient, trigger.Spec.Namespaces)
	deliveryGate := r.get(triggerRefName)
	jobCounter := sharedPiTriggerJobCounterRegistry.get(triggerRefName)
	maxJobs := int(trigger.Spec.MaxJobs)

	ctx, cancel := context.WithCancel(r.ctx)
	r.runningTriggersLock.Lock()
	r.runningTriggers[triggerRefName] = cancel
	r.runningTriggersLock.Unlock()
	recordControllerSessionStart(metricControllerPiTrigger)
	if r.DeletionWatcher != nil {
		r.DeletionWatcher.RegisterTask(triggerRefName, cancel)
	}

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
			return nil
		}
		sessionWatchers = reopened
		sessionGen++
		return nil
	}

	recordRuntimeError := func(errorReason, errorResourceVersion string) {
		patchCtx, patchCancel := context.WithTimeout(r.ctx, time.Minute)
		defer patchCancel()

		latest := &triggersv1.PiTrigger{}
		if err := r.Get(patchCtx, client.ObjectKeyFromObject(trigger), latest); err != nil {
			return
		}
		if latest.Generation != trigger.Generation {
			return
		}
		if latest.Status.Phase == triggersv1.TriggerPhaseError && latest.Status.ErrorReason == errorReason && latest.Status.ErrorResourceVersion == errorResourceVersion {
			return
		}

		patched := latest.DeepCopy()
		patched.Status.ErrorTime = metav1.Now()
		patched.Status.ErrorReason = errorReason
		patched.Status.ErrorResourceVersion = errorResourceVersion
		_ = r.Status().Patch(patchCtx, patched, client.MergeFrom(latest))
	}

	logger := logf.FromContext(ctx).WithValues("trigger", triggerRefName, "grv", gvr.String())
	logger.Info("Watcher started")

	const (
		minReconnectBackoff = time.Second
		maxReconnectBackoff = 30 * time.Second
	)

	for i := 1; i <= int(concurrency); i++ {
		recordWatcherGoroutineStart(metricControllerPiTrigger)
		go func() {
			defer recordWatcherGoroutineDone(metricControllerPiTrigger)
			reconnectBackoff := minReconnectBackoff
			reconnectWatchStream := func(reason string, activeWatchers []watch.Interface, activeGen uint64) bool {
				stopWatchers(activeWatchers)
				if ctx.Err() != nil {
					return false
				}

				logger.V(1).Info("Watch stream reconnecting", "reason", reason, "gen", activeGen, "lastResourceVersion", *lastResourceVersion.Load())
				for {
					if err := reconnect(activeGen); err != nil {
						logger.Error(err, "Reconnect failed", "reason", reason, "gen", activeGen, "retryAfter", reconnectBackoff.String())
						if !sleepContext(ctx, reconnectBackoff) {
							return false
						}
						if reconnectBackoff < maxReconnectBackoff {
							reconnectBackoff *= 2
							if reconnectBackoff > maxReconnectBackoff {
								reconnectBackoff = maxReconnectBackoff
							}
						}
						continue
					}

					logger.V(1).Info("Watch stream reconnected", "reason", reason, "gen", activeGen)
					reconnectBackoff = minReconnectBackoff
					return true
				}
			}

			for {
				watchersMu.Lock()
				activeWatchers := sessionWatchers
				activeGen := sessionGen
				watchersMu.Unlock()

				_, data, ok := reflect.Select(buildWatcherSelectCases(activeWatchers, ctx.Done()))
				if !ok {
					if !reconnectWatchStream("closed", activeWatchers, activeGen) {
						return
					}
					continue
				}

				reconnectBackoff = minReconnectBackoff
				event := data.Interface().(watch.Event)
				if event.Type == watch.Error {
					if !reconnectWatchStream("error event", activeWatchers, activeGen) {
						return
					}
					continue
				} else if event.Object == nil {
					continue
				}

				if event.Type == watch.Bookmark {
					bookmark, ok := event.Object.(*metav1.PartialObjectMetadata)
					if !ok || bookmark == nil {
						continue
					}
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

				if _, ok := eventTypes[string(event.Type)]; !ok {
					continue
				}

				event.Object.GetObjectKind().SetGroupVersionKind(gvk)
				unstructuredObj, ok := event.Object.(*unstructured.Unstructured)
				if !ok {
					logger.Error(fmt.Errorf("event conversion to unstructured failed"), "Skipping malformed watch event", "eventType", event.Type)
					continue
				}

				if trigger.Spec.EventFilter != "" {
					renderedMatch, err := renderTemplateToString(compiledTemplates, filterTemplateName, unstructuredObj.Object)
					if err != nil {
						logger.Error(err, "Skipping watch event because event filter evaluation failed", "eventType", event.Type, "resourceVersion", unstructuredObj.GetResourceVersion(), "name", unstructuredObj.GetName(), "namespace", unstructuredObj.GetNamespace())
						continue
					}
					if renderedMatch != trueString {
						continue
					}
				}

				metadata, ok := unstructuredObj.Object["metadata"].(map[string]interface{})
				if !ok {
					logger.Error(fmt.Errorf("object metadata is missing or invalid"), "Skipping malformed watch event", "eventType", event.Type, "resourceVersion", unstructuredObj.GetResourceVersion())
					continue
				}
				if delay := deliveryGate.delay(); delay > 0 {
					recordDeliveryBackoff(kindPiTrigger, triggerRefName)
					logger.V(1).Info("Delaying job creation due to sustained dispatch failure", "name", metadata["name"], "namespace", metadata["namespace"], "delay", delay.String(), "consecutiveFailures", deliveryGate.consecutiveFailures())
					if !sleepContext(ctx, delay) {
						return
					}
				}

				for {
					slotReserved := false
					for {
						reserved, runningJobs, err := jobCounter.reserveSlot(ctx, r.Client, trigger, maxJobs)
						if err != nil {
							logger.Error(err, "Pi worker job slot refresh failed, retrying", "name", metadata["name"], "namespace", metadata["namespace"], "resourceVersion", unstructuredObj.GetResourceVersion(), "retryAfter", piTriggerJobSlotRetryDelay.String())
							if !sleepContext(ctx, piTriggerJobSlotRetryDelay) {
								return
							}
							continue
						}
						if reserved {
							slotReserved = true
							break
						}
						logger.V(1).Info("Pi worker event requeued because maxJobs is reached", "name", metadata["name"], "namespace", metadata["namespace"], "resourceVersion", unstructuredObj.GetResourceVersion(), "runningJobs", runningJobs, "maxJobs", maxJobs, "retryAfter", piTriggerJobSlotRetryDelay.String())
						if !sleepContext(ctx, piTriggerJobSlotRetryDelay) {
							return
						}
					}

					jobName, rv, err := r.dispatchPiJob(ctx, triggerRefName, trigger, event, unstructuredObj)
					if err != nil {
						if slotReserved {
							jobCounter.releaseReservedSlot()
						}
						deliveryGate.recordFailure()
						emitTriggerCallFailureEvent(r.Recorder, trigger, triggerRefName, "CREATE", "job", event.Type, metadata, err)
						recordRuntimeError(fmt.Sprintf("job dispatch failed: %v", err), unstructuredObj.GetResourceVersion())
						retryDelay := deliveryGate.delay()
						if retryDelay <= 0 {
							retryDelay = time.Second
						}
						logger.Error(err, "Pi worker job dispatch failed, retrying", "name", metadata["name"], "namespace", metadata["namespace"], "resourceVersion", unstructuredObj.GetResourceVersion(), "retryAfter", retryDelay.String())
						if !sleepContext(ctx, retryDelay) {
							return
						}
						continue
					}

					deliveryGate.recordSuccess()
					logger.Info("Pi worker job dispatched", "job", jobName, "resourceVersion", rv, "eventType", event.Type)
					for {
						lrv := lastResourceVersion.Load()
						if natsort.Compare(rv, *lrv) {
							break
						} else if lastResourceVersion.CompareAndSwap(lrv, &rv) {
							break
						}
					}
					break
				}
			}
		}()
	}

	return nil
}

func (r *PiTriggerReconciler) dispatchPiJob(ctx context.Context, triggerRefName string, trigger *triggersv1.PiTrigger, event watch.Event, obj *unstructured.Unstructured) (string, string, error) {
	rv := obj.GetResourceVersion()
	if rv == "" {
		return "", "", errors.New("watched object has no resourceVersion")
	}

	eventPayload := piTriggerEventInput{
		TriggerRefName:   triggerRefName,
		TriggerName:      trigger.Name,
		TriggerNamespace: trigger.Namespace,
		EventType:        string(event.Type),
		ResourceVersion:  rv,
		Object:           obj.Object,
	}
	metadataPayload := piTriggerJobMetadata{
		TriggerRefName:   triggerRefName,
		TriggerName:      trigger.Name,
		TriggerNamespace: trigger.Namespace,
		EventType:        string(event.Type),
		ResourceVersion:  rv,
	}

	workerPrompt, err := buildPiTriggerWorkerPrompt(trigger.Spec)
	if err != nil {
		return "", "", err
	}

	return r.createPiWorkerJob(ctx, triggerRefName, trigger, eventPayload, metadataPayload, workerPrompt)
}

func (r *PiTriggerReconciler) dispatchOwnerLeaseTimeoutJob(ctx context.Context, triggerRefName string, trigger *triggersv1.PiTrigger) error {
	leaseName, ok, err := r.expiredOwnerLeaseName(ctx, trigger, time.Now().UTC())
	if err != nil || !ok {
		return err
	}

	payload, err := runtime.DefaultUnstructuredConverter.ToUnstructured(trigger.DeepCopy())
	if err != nil {
		return err
	}

	timeoutMessage := fmt.Sprintf("owner lease %s timed out", leaseName)
	rv := trigger.GetResourceVersion()
	if rv == "" {
		rv = "0"
	}
	eventPayload := piTriggerEventInput{
		TriggerRefName:    triggerRefName,
		TriggerName:       trigger.Name,
		TriggerNamespace:  trigger.Namespace,
		EventType:         string(triggersv1.EventTypeDeleted),
		ResourceVersion:   rv,
		Message:           timeoutMessage,
		TimedOutLeaseName: leaseName,
		Object:            payload,
	}
	metadataPayload := piTriggerJobMetadata{
		TriggerRefName:    triggerRefName,
		TriggerName:       trigger.Name,
		TriggerNamespace:  trigger.Namespace,
		EventType:         string(triggersv1.EventTypeDeleted),
		ResourceVersion:   rv,
		Message:           timeoutMessage,
		TimedOutLeaseName: leaseName,
	}
	prompt, err := buildPiTriggerWorkerPrompt(
		trigger.Spec,
		fmt.Sprintf("The trigger owner lease %s timed out. Use the event payload and metadata to handle timeout cleanup for this deleted trigger.", leaseName),
	)
	if err != nil {
		return err
	}
	_, _, err = r.createPiWorkerJob(ctx, triggerRefName, trigger, eventPayload, metadataPayload, prompt)
	return err
}

func (r *PiTriggerReconciler) createPiWorkerJob(ctx context.Context, triggerRefName string, trigger *triggersv1.PiTrigger, eventPayload piTriggerEventInput, metadataPayload piTriggerJobMetadata, workerPrompt string) (string, string, error) {
	rv := eventPayload.ResourceVersion
	if rv == "" {
		return "", "", errors.New("watched object has no resourceVersion")
	}
	objectName := ""
	objectNamespace := trigger.Namespace
	if metadata, ok := eventPayload.Object["metadata"].(map[string]interface{}); ok {
		if name, ok := metadata["name"].(string); ok {
			objectName = name
		}
		if namespace, ok := metadata["namespace"].(string); ok && namespace != "" {
			objectNamespace = namespace
		}
	}
	nameHash := shortHash(strings.Join([]string{triggerRefName, eventPayload.EventType, objectNamespace, objectName, rv}, "|"))
	jobName := buildPiTriggerResourceName(trigger.Name, nameHash, "job")
	configMapName := buildPiTriggerResourceName(trigger.Name, nameHash, "input")
	if eventPayload.Message != "" {
		eventPayload.Message = buildPiTriggerTimeoutMessage(eventPayload.Message, triggerRefName, rv, jobName, configMapName)
	}
	if metadataPayload.Message != "" {
		metadataPayload.Message = buildPiTriggerTimeoutMessage(metadataPayload.Message, triggerRefName, rv, jobName, configMapName)
	}

	eventBytes, err := json.MarshalIndent(eventPayload, "", "  ")
	if err != nil {
		return "", "", err
	}
	metadataBytes, err := json.MarshalIndent(metadataPayload, "", "  ")
	if err != nil {
		return "", "", err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: trigger.Namespace,
			Labels: map[string]string{
				piTriggerManagedLabel:     "true",
				piTriggerTriggerNameLabel: trigger.Name,
			},
		},
		Data: map[string]string{
			"event.json":    string(eventBytes),
			"metadata.json": string(metadataBytes),
		},
	}
	persistAfterTriggerDeletion := trigger.GetDeletionTimestamp() != nil && !trigger.GetDeletionTimestamp().IsZero()
	if !persistAfterTriggerDeletion {
		if err := controllerutil.SetControllerReference(trigger, configMap, r.Scheme); err != nil {
			return "", "", err
		}
	}
	if err := r.Create(ctx, configMap); err != nil && !apierrors.IsAlreadyExists(err) {
		return "", "", err
	}

	workerArgs := buildPiTriggerWorkerArgs(workerPrompt, trigger.Spec.Agent)
	activeDeadlineSeconds := resolvePiTriggerActiveDeadlineSeconds(trigger.Spec.Agent)

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: trigger.Namespace,
			Labels: map[string]string{
				piTriggerManagedLabel:     "true",
				piTriggerTriggerNameLabel: trigger.Name,
			},
			Annotations: map[string]string{
				piTriggerInputConfigMapAnnotation:  configMapName,
				piTriggerEventTypeAnnotation:       eventPayload.EventType,
				piTriggerResourceVersionAnnotation: rv,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            trigger.Spec.Agent.BackoffLimit,
			ActiveDeadlineSeconds:   activeDeadlineSeconds,
			TTLSecondsAfterFinished: trigger.Spec.Agent.TTLSecondsAfterFinished,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						piTriggerManagedLabel:     "true",
						piTriggerTriggerNameLabel: trigger.Name,
					},
				},
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyNever,
					ServiceAccountName: trigger.Spec.Agent.ServiceAccountName,
					Volumes: []corev1.Volume{{
						Name: piTriggerInputVolumeName,
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: configMapName}},
						},
					}, {
						Name: piTriggerAgentSecretVolumeName,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{SecretName: trigger.Spec.Agent.ConfigSecretRef.Name},
						},
					}, {
						Name: piTriggerPromptsVolumeName,
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: trigger.Spec.Agent.PromptsConfigMapRef.Name}},
						},
					}, {
						Name: piTriggerSkillsVolumeName,
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: trigger.Spec.Agent.SkillsConfigMapRef.Name}},
						},
					}},
					Containers: []corev1.Container{{
						Name:            piTriggerWorkerContainerName,
						Image:           trigger.Spec.Agent.Image,
						ImagePullPolicy: trigger.Spec.Agent.ImagePullPolicy,
						WorkingDir:      trigger.Spec.Agent.WorkingDir,
						Args:            workerArgs,
						Env: append([]corev1.EnvVar{{
							Name:  "HOME",
							Value: piTriggerWorkerHomeDir,
						}}, trigger.Spec.Agent.Env...),
						EnvFrom:   trigger.Spec.Agent.EnvFrom,
						Resources: trigger.Spec.Agent.Resources,
						VolumeMounts: []corev1.VolumeMount{{
							Name:      piTriggerInputVolumeName,
							MountPath: piTriggerInputMountPath,
							ReadOnly:  true,
						}, {
							Name:      piTriggerAgentSecretVolumeName,
							MountPath: piTriggerAgentConfigMountPath,
							ReadOnly:  true,
						}, {
							Name:      piTriggerPromptsVolumeName,
							MountPath: piTriggerAgentPromptsMountPath,
							ReadOnly:  true,
						}, {
							Name:      piTriggerSkillsVolumeName,
							MountPath: piTriggerAgentSkillsMountPath,
							ReadOnly:  true,
						}},
					}},
				},
			},
		},
	}
	if !persistAfterTriggerDeletion {
		if err := controllerutil.SetControllerReference(trigger, job, r.Scheme); err != nil {
			return "", "", err
		}
	}
	if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		return "", "", err
	}

	return jobName, rv, nil
}

func (r *PiTriggerReconciler) expiredOwnerLeaseName(ctx context.Context, trigger *triggersv1.PiTrigger, now time.Time) (string, bool, error) {
	if trigger == nil {
		return "", false, nil
	}

	for _, owner := range trigger.GetOwnerReferences() {
		if owner.APIVersion != coordinationv1.SchemeGroupVersion.String() || owner.Kind != "Lease" || owner.Name == "" {
			continue
		}

		ownerLease := &coordinationv1.Lease{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: trigger.Namespace, Name: owner.Name}, ownerLease); err != nil {
			if apierrors.IsNotFound(err) {
				return owner.Name, true, nil
			}
			return "", false, err
		}
		if leaseTimedOut(ownerLease, now) {
			return owner.Name, true, nil
		}
	}

	return "", false, nil
}

func buildPiTriggerTimeoutMessage(baseMessage, triggerRefName, resourceVersion, jobName, inputConfigMapName string) string {
	parts := []string{baseMessage}
	if triggerRefName != "" {
		parts = append(parts, fmt.Sprintf("trigger=%s", triggerRefName))
	}
	if resourceVersion != "" {
		parts = append(parts, fmt.Sprintf("resourceVersion=%s", resourceVersion))
	}
	if jobName != "" {
		parts = append(parts, fmt.Sprintf("job=%s", jobName))
	}
	if inputConfigMapName != "" {
		parts = append(parts, fmt.Sprintf("inputConfigMap=%s", inputConfigMapName))
	}
	return strings.Join(parts, "; ")
}

func buildPiTriggerWorkerPrompt(triggerSpec triggersv1.PiTriggerSpec, extraSections ...string) (string, error) {
	triggerSpecSkill, err := buildPiTriggerSpecSkill(triggerSpec)
	if err != nil {
		return "", err
	}

	sections := []string{
		triggerSpecSkill,
		"Task:\nHandle the triggering Kubernetes event using the mounted Pi agent configuration and the provided event payload.",
		fmt.Sprintf("The triggering Kubernetes event payload is available in the container at %s.", piTriggerEventFilePath),
		fmt.Sprintf("Trigger metadata is available in the container at %s.", piTriggerMetadataFilePath),
	}
	sections = append(sections, extraSections...)
	sections = append(sections, "Use pi tools to inspect these files as needed before acting.")
	return strings.Join(sections, "\n\n"), nil
}

func buildPiTriggerSpecSkill(triggerSpec triggersv1.PiTriggerSpec) (string, error) {
	payload, err := json.Marshal(triggerSpec)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sub-agent defaults base64://%s", base64.StdEncoding.EncodeToString(payload)), nil
}

func buildPiTriggerWorkerArgs(prompt string, agent triggersv1.PiAgentSpec) []string {
	args := []string{"--mode", "json"}
	if agent.NoExtensions {
		args = append(args, "--no-extensions")
	}
	for _, extension := range agent.Extensions {
		if strings.TrimSpace(extension) == "" {
			continue
		}
		args = append(args, "--extension", extension)
	}
	args = append(args, "--no-session")
	if agent.Provider != "" {
		args = append(args, "--provider", agent.Provider)
	}
	if agent.Model != "" {
		args = append(args, "--model", agent.Model)
	}
	args = append(args, "-p", fmt.Sprintf("Execute the necessary tool or shell commands to complete the request below.\n\nPrompt: %s", strings.TrimSpace(prompt)))
	return args
}

func resolvePiTriggerActiveDeadlineSeconds(agent triggersv1.PiAgentSpec) *int64 {
	if agent.ActiveDeadlineSeconds != nil {
		return agent.ActiveDeadlineSeconds
	}
	if agent.Timeout.Duration <= 0 {
		return nil
	}

	seconds := int64(agent.Timeout.Duration / time.Second)
	if agent.Timeout.Duration%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	return ptr.To(seconds)
}

func (r *PiTriggerReconciler) latestDispatchedResourceVersion(ctx context.Context, trigger *triggersv1.PiTrigger) (string, error) {
	jobList := &batchv1.JobList{}
	if err := r.List(ctx, jobList, &client.ListOptions{
		Namespace:     trigger.Namespace,
		LabelSelector: piTriggerJobLabelSelector(trigger.Name),
	}); err != nil {
		return "", err
	}

	latest := ""
	for _, job := range jobList.Items {
		rv := job.Annotations[piTriggerResourceVersionAnnotation]
		if rv == "" {
			continue
		}
		if latest == "" || natsort.Compare(latest, rv) {
			latest = rv
		}
	}

	return latest, nil
}

func validatePiAgentConfigRefs(ctx context.Context, getter kubeGetter, namespace string, agent triggersv1.PiAgentSpec) error {
	if strings.TrimSpace(agent.ConfigSecretRef.Name) == "" {
		return errors.Join(ErrInvalidTriggerContent, errors.New("agent.configSecretRef.name is required"))
	}
	if strings.TrimSpace(agent.PromptsConfigMapRef.Name) == "" {
		return errors.Join(ErrInvalidTriggerContent, errors.New("agent.promptsConfigMapRef.name is required"))
	}
	if strings.TrimSpace(agent.SkillsConfigMapRef.Name) == "" {
		return errors.Join(ErrInvalidTriggerContent, errors.New("agent.skillsConfigMapRef.name is required"))
	}

	secret := &corev1.Secret{}
	if err := getter.Get(ctx, client.ObjectKey{Namespace: namespace, Name: agent.ConfigSecretRef.Name}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return errors.Join(ErrInvalidTriggerContent, fmt.Errorf("agent.configSecretRef.name references missing Secret %s/%s", namespace, agent.ConfigSecretRef.Name))
		}
		return err
	}

	requiredKeys := []string{"settings.json", "models.json", "models-store.json", "auth.json"}
	for _, key := range requiredKeys {
		if _, ok := secret.Data[key]; !ok {
			return errors.Join(ErrInvalidTriggerContent, fmt.Errorf("agent config secret %s/%s missing required key %q", namespace, agent.ConfigSecretRef.Name, key))
		}
	}

	for fieldName, configMapName := range map[string]string{
		"agent.promptsConfigMapRef.name": agent.PromptsConfigMapRef.Name,
		"agent.skillsConfigMapRef.name":  agent.SkillsConfigMapRef.Name,
	} {
		configMap := &corev1.ConfigMap{}
		if err := getter.Get(ctx, client.ObjectKey{Namespace: namespace, Name: configMapName}, configMap); err != nil {
			if apierrors.IsNotFound(err) {
				return errors.Join(ErrInvalidTriggerContent, fmt.Errorf("%s references missing ConfigMap %s/%s", fieldName, namespace, configMapName))
			}
			return err
		}
	}

	return nil
}

func buildPiTriggerResourceName(triggerName, suffix, kind string) string {
	base := strings.ToLower(triggerName)
	base = strings.ReplaceAll(base, "_", "-")
	base = strings.ReplaceAll(base, ".", "-")
	base = strings.ReplaceAll(base, "/", "-")
	base = strings.Trim(base, "-")
	if len(base) > 30 {
		base = base[:30]
	}
	return fmt.Sprintf("pi-%s-%s-%s", kind, base, suffix[:10])
}

func shortHash(raw string) string {
	sum := sha1.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (r *PiTriggerReconciler) WatchInit(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	existingTriggers := triggersv1.PiTriggerList{}
	if err := r.List(ctx, &existingTriggers); err != nil {
		return err
	}

	for _, trigger := range existingTriggers.Items {
		refName := trigger.Namespace + "/" + trigger.Name
		if r.PartitionController != nil && !r.PartitionController.OwnsObject(&trigger) {
			r.stopRunningTrigger(refName)
			r.remove(refName)
			sharedPiTriggerJobCounterRegistry.remove(refName)
			continue
		}
		r.runningTriggersLock.Lock()
		_, alreadyRunning := r.runningTriggers[refName]
		r.runningTriggersLock.Unlock()
		if alreadyRunning {
			continue
		}
		triggerMu := r.triggerLock(refName)
		triggerMu.Lock()
		initErr := r.createTrigger(refName, &trigger)
		triggerMu.Unlock()
		if initErr != nil {
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

func (r *PiTriggerReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager, maxConcurrentReconciles int, wg *sync.WaitGroup) error {
	r.ctx = ctx
	r.Recorder = mgr.GetEventRecorderFor("pitrigger-controller")
	r.runningTriggersLock = sync.Mutex{}
	r.runningTriggers = map[string]func(){}
	r.triggerLocksLock = sync.Mutex{}
	r.triggerLocks = map[string]*sync.Mutex{}
	r.init()
	if r.DeletionWatcher == nil {
		r.DeletionWatcher = triggerwatcher.NewGlobalDeletionWatcher()
	}
	if r.PartitionController == nil {
		r.PartitionController = partition.NewSingleWorkerController()
	}
	if informer, err := mgr.GetCache().GetInformer(ctx, &triggersv1.PiTrigger{}); err != nil {
		return err
	} else if err := r.DeletionWatcher.Start(ctx, informer); err != nil {
		return err
	}
	if r.PartitionController.Mode() == partition.ModeDistributedPartition {
		r.PartitionController.AddChangeListener(func(listenerCtx context.Context) {
			if err := r.WatchInit(listenerCtx); err != nil {
				logf.FromContext(listenerCtx).Error(err, "distributed PiTrigger resync failed")
			}
		})
	}

	recordControllerRegistered(metricControllerPiTrigger)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer recordControllerStopped(metricControllerPiTrigger)
		<-ctx.Done()
		r.clear()
		sharedPiTriggerJobCounterRegistry.clear()
		r.runningTriggersLock.Lock()
		for refName := range r.runningTriggers {
			r.stopRunningTriggerLocked(refName)
		}
		r.runningTriggersLock.Unlock()

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
		For(&triggersv1.PiTrigger{}).
		Named("pitrigger").
		WithOptions(controller.Options{
			NeedLeaderElection:      ptr.To(true),
			MaxConcurrentReconciles: maxConcurrentReconciles,
			RecoverPanic:            ptr.To(true),
			Logger:                  mgr.GetLogger(),
		}).
		Complete(r)
}
