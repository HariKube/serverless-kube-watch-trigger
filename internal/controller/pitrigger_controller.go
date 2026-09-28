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
	"regexp"
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
	piTriggerManagedLabel                    = "triggers.harikube.info/pitrigger-job"
	piTriggerTriggerNameLabel                = "triggers.harikube.info/pitrigger-name"
	piTriggerEventTypeAnnotation             = "triggers.harikube.info/event-type"
	piTriggerResourceVersionAnnotation       = "triggers.harikube.info/resource-version"
	piTriggerSessionLabel                    = "harikube.info/session"
	piTriggerRoundLabel                      = "harikube.info/round"
	piTriggerWorkerLabel                     = "harikube.info/worker"
	piTriggerTraceIDLabel                    = "harikube.info/trace-id"
	piTriggerSessionSecretAnnotation         = "harikube.info/session-secret"
	piTriggerOutputLocationAnnotation        = "harikube.info/output-location"
	piTriggerWorkerContainerName             = "pi-agent"
	piTriggerWorkerInputEnvVar               = "PI_TRIGGER_INPUT_BASE64"
	piTriggerSubAgentDefaultsEnvVar          = "PI_SUBAGENT_DEFAULTS_BASE64"
	piTriggerRuntimeExtensionPath            = "/root/.pi/agent/extensions/pitrigger-input.ts"
	piTriggerTimeoutDiagnosticsExtensionPath = "/root/.pi/agent/extensions/job-status.ts"
	piTriggerServiceDiscoveryExtensionPath   = "/root/.pi/agent/extensions/kubernetes-service-discovery.ts"
	piTriggerAgentSecretVolumeName           = "pi-agent-config"
	piTriggerPromptsVolumeName               = "pi-agent-prompts"
	piTriggerSkillsVolumeName                = "pi-agent-skills"
	piTriggerWorkerHomeDir                   = "/tmp/pi-home"
	piTriggerAgentConfigMountPath            = piTriggerWorkerHomeDir + "/.pi/agent"
	piTriggerAgentPromptsMountPath           = piTriggerAgentConfigMountPath + "/prompts"
	piTriggerAgentSkillsMountPath            = piTriggerAgentConfigMountPath + "/skills"
)

var (
	piTriggerSessionTriggerNamePattern   = regexp.MustCompile(`^pi-subagent-(.+)-r([0-9]+)-w([0-9]+)-trigger$`)
	piTriggerSessionTriggerNamePatternV2 = regexp.MustCompile(`^pi-session-[0-9a-f]{8}-(.+)-r([0-9]+)-w([0-9]+)-trigger$`)
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

	// Structured session/job identity useful for wake-up and restore
	SessionID         string `json:"sessionId,omitempty"`
	Round             string `json:"round,omitempty"`
	WorkerIndex       string `json:"workerIndex,omitempty"`
	TraceID           string `json:"traceId,omitempty"`
	SessionSecretName string `json:"sessionSecretName,omitempty"`
	JobName           string `json:"jobName,omitempty"`
}

type piTriggerRuntimeInput struct {
	Payload  map[string]interface{} `json:"payload"`
	Metadata piTriggerJobMetadata   `json:"metadata"`
}

type piTriggerSubAgentDefaults struct {
	Namespace string                 `json:"namespace"`
	TraceID   string                 `json:"traceId,omitempty"`
	Agent     triggersv1.PiAgentSpec `json:"agent"`
}

type piTriggerSession struct {
	stop             func()
	sessionLease     triggerSessionLease
	leaseRenewerDone chan struct{}
}

// PiTriggerReconciler reconciles a PiTrigger object.
type PiTriggerReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	DynamicClient *dynamic.DynamicClient
	Recorder      record.EventRecorder

	PartitionController *partition.Controller
	DeletionWatcher     *triggerwatcher.GlobalDeletionWatcher

	ctx                    context.Context
	runningTriggersLock    sync.Mutex
	runningTriggers        map[string]func()
	runningTriggerSessions map[string]*piTriggerSession

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
	stopFn := r.detachRunningTriggerLocked(triggerRefName)
	r.runningTriggersLock.Unlock()

	if stopFn != nil {
		stopFn()
	}
}

func (r *PiTriggerReconciler) detachRunningTriggerLocked(triggerRefName string) func() {
	var stopFn func()
	if cancel, ok := r.runningTriggers[triggerRefName]; ok {
		stopFn = cancel
	}
	if stopFn == nil {
		if session, ok := r.runningTriggerSessions[triggerRefName]; ok && session != nil {
			stopFn = session.stop
		}
	}
	delete(r.runningTriggers, triggerRefName)
	delete(r.runningTriggerSessions, triggerRefName)
	if stopFn != nil {
		recordControllerSessionStop(metricControllerPiTrigger)
	}
	if r.DeletionWatcher != nil {
		r.DeletionWatcher.UnregisterTask(triggerRefName)
	}
	return stopFn
}

// +kubebuilder:rbac:groups=triggers.harikube.info,resources=pitriggers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=pitriggers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=pitriggers/finalizers,verbs=update
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=create;delete;get;list;watch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete
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

	if done, err := r.preflightReconcile(ctx, logger, triggerRefName, &trigger); done || err != nil {
		return ctrl.Result{}, err
	}

	// Opt-in per-trigger reconcile lease (spec.lockDuration). It is claimed
	// before the running session is torn down so a trigger whose lease is held
	// by another replica keeps its current session instead of going dark until
	// the requeue fires.
	annotationLeaseAcquired, annotationLeaseRequeue, err := acquireAnnotationLease(
		ctx,
		logger,
		r.Client,
		&trigger,
		trigger.Spec.LockDuration.Duration,
	)
	if err != nil {
		return ctrl.Result{}, err
	}
	if annotationLeaseRequeue != nil {
		return *annotationLeaseRequeue, nil
	}
	triggerSettled := false
	if annotationLeaseAcquired {
		defer func() {
			// A failed reconcile keeps the lease so the next attempt (or the
			// requeue that follows) still observes an exclusive claim.
			if !triggerSettled {
				return
			}
			_ = releaseAnnotationLease(ctx, logger, r.Client, &trigger)
		}()
	}

	r.stopRunningTrigger(triggerRefName)

	recoveryRestart := !trigger.Status.ErrorTime.IsZero() && trigger.Status.LastGeneration == trigger.Generation
	patchedTrigger := trigger.DeepCopy()
	patchedTrigger.Status.LastGeneration = trigger.Generation

	createResult, err := r.createTrigger(ctx, logger, triggerRefName, &trigger)
	if err != nil {
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
	if createResult != nil {
		return *createResult, nil
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
	triggerSettled = true

	return ctrl.Result{}, nil
}

func (r *PiTriggerReconciler) preflightReconcile(ctx context.Context, logger logr.Logger, triggerRefName string, trigger *triggersv1.PiTrigger) (bool, error) {
	if trigger.DeletionTimestamp != nil || !trigger.DeletionTimestamp.IsZero() {
		logger.Info("Trigger deleted")
		// Prefer owner-lease timeout handling if an owner Lease reference exists
		_, leaseExpired, leaseErr := r.expiredOwnerLeaseName(ctx, trigger, time.Now().UTC())
		if leaseErr != nil {
			logger.Error(leaseErr, "Failed to check for expired owner lease")
		} else if leaseExpired {
			// Existing behavior: dispatch owner-lease timed out job
			if err := r.dispatchOwnerLeaseTimeoutJob(ctx, triggerRefName, trigger); err != nil {
				logger.Error(err, "Trigger deletion timeout job dispatch failed")
			}
		} else {
			// No expired owner lease; if the trigger session itself timed out, dispatch
			// a session-timeout job so that cleanup can run with a DELETED payload.
			sessionTimeout := trigger.Spec.Timeout.Duration
			if sessionTimeout > 0 && time.Now().UTC().After(trigger.CreationTimestamp.Add(sessionTimeout)) {
				if err := r.dispatchTriggerSessionTimeoutJob(ctx, triggerRefName, trigger); err != nil {
					logger.Error(err, "Trigger deletion session-timeout job dispatch failed")
				}
			}
		}
		r.stopRunningTrigger(triggerRefName)
		r.remove(triggerRefName)
		sharedPiTriggerJobCounterRegistry.remove(triggerRefName)
		return true, nil
	}
	if r.PartitionController != nil && !r.PartitionController.OwnsObject(trigger) {
		r.stopRunningTrigger(triggerRefName)
		r.remove(triggerRefName)
		sharedPiTriggerJobCounterRegistry.remove(triggerRefName)
		return true, nil
	}
	if trigger.Status.Phase == triggersv1.TriggerPhaseRunning {
		if err := r.clearExpiredAnnotationLease(ctx, logger, trigger); err != nil {
			return true, err
		}
		if trigger.Status.LastGeneration == trigger.Generation {
			return true, nil
		}
	}
	if trigger.Generation == 1 && trigger.Status.LastGeneration == 0 {
		logger.Info("Trigger created")
		return false, nil
	}

	logger.Info("Trigger updated")
	return false, nil
}

// clearExpiredAnnotationLease removes an annotation lease that a previous
// reconcile left behind. A lease that is still valid is left in place so a
// replica that is mid-reconcile keeps its claim, and the current reconcile
// requeues on it instead of racing ahead.
func (r *PiTriggerReconciler) clearExpiredAnnotationLease(ctx context.Context, logger logr.Logger, trigger *triggersv1.PiTrigger) error {
	return clearExpiredAnnotationLease(ctx, logger, r.Client, trigger, trigger.Spec.LockDuration.Duration)
}

//nolint:gocyclo
func (r *PiTriggerReconciler) acquireSessionLease(ctx context.Context, logger logr.Logger, triggerRefName string, trigger *triggersv1.PiTrigger) (triggerSessionLease, *ctrl.Result, error) {
	sessionLease := newTriggerSessionLease("pitrigger", trigger, triggerRefName, trigger.Spec.LockDuration.Duration)
	leaseResult, err := lease.TryAcquireCoordinationLease(
		ctx,
		r.Client,
		client.ObjectKey{Namespace: sessionLease.namespace, Name: sessionLease.name},
		sessionLease.holderIdentity,
		time.Now().UTC(),
		sessionLease.duration,
	)
	if err != nil {
		logger.Error(err, "Trigger session lease acquisition failed", "lease", sessionLease.name)
		return triggerSessionLease{}, nil, err
	}
	if leaseResult.RequeueAfter > 0 {
		logger.V(1).Info("Trigger session lease is held by another replica, requeueing", "lease", sessionLease.name, "requeueAfter", leaseResult.RequeueAfter.String())
		return triggerSessionLease{}, &ctrl.Result{RequeueAfter: leaseResult.RequeueAfter}, nil
	}
	return sessionLease, nil, nil
}

func (r *PiTriggerReconciler) startSessionLeaseRenewer(ctx context.Context, logger logr.Logger, triggerRefName string, session *piTriggerSession) {
	if session == nil {
		return
	}
	renewEvery := session.sessionLease.duration / 3
	if renewEvery < time.Second {
		renewEvery = time.Second
	}
	go func() {
		if session.leaseRenewerDone != nil {
			defer close(session.leaseRenewerDone)
		}
		ticker := time.NewTicker(renewEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if ctx.Err() != nil {
				return
			}

			renewed, err := lease.RenewCoordinationLease(
				ctx,
				r.Client,
				client.ObjectKey{Namespace: session.sessionLease.namespace, Name: session.sessionLease.name},
				session.sessionLease.holderIdentity,
				time.Now().UTC(),
				session.sessionLease.duration,
			)
			if ctx.Err() != nil {
				return
			}
			if err == nil && renewed {
				continue
			}
			if err != nil {
				logger.Error(err, "Trigger session lease renew failed", "lease", session.sessionLease.name)
			} else {
				logger.Info("Trigger session lease lost; stopping watcher session", "lease", session.sessionLease.name)
			}

			r.runningTriggersLock.Lock()
			var stopFn func()
			if currentSession, ok := r.runningTriggerSessions[triggerRefName]; ok && currentSession == session {
				stopFn = r.detachRunningTriggerLocked(triggerRefName)
			}
			r.runningTriggersLock.Unlock()
			if stopFn != nil {
				stopFn()
			}
			return
		}
	}()
}

//nolint:gocyclo
func (r *PiTriggerReconciler) createTrigger(reconcileCtx context.Context, reconcileLogger logr.Logger, triggerRefName string, trigger *triggersv1.PiTrigger) (*ctrl.Result, error) {
	resourceVersion := triggerResourceVersion(trigger.Status.ErrorResourceVersion)
	if trigger.ResourceVersion != "" && natsort.Compare(resourceVersion, trigger.ResourceVersion) {
		resourceVersion = trigger.ResourceVersion
	}
	if latestJobResourceVersion, err := r.latestDispatchedResourceVersion(r.ctx, trigger); err != nil {
		return nil, err
	} else if latestJobResourceVersion != "" && natsort.Compare(resourceVersion, latestJobResourceVersion) {
		resourceVersion = latestJobResourceVersion
	}
	gvr, gvk := buildTriggerResourceInfo(trigger.Spec.Resource)
	eventTypes := buildTriggerEventTypes(trigger.Spec.EventType)

	compiledTemplates := map[string]*template.Template{}
	if trigger.Spec.EventFilter != "" {
		if err := addCompiledTemplate(compiledTemplates, filterTemplateName, fmt.Sprintf("{{if %s}}true{{end}}", trigger.Spec.EventFilter), nil); err != nil {
			return nil, errors.Join(err, ErrInvalidTriggerContent, errors.New("failed to parse filter template"))
		}
	}

	depFetchCtx, depFetchCancel := context.WithTimeout(r.ctx, time.Minute)
	defer depFetchCancel()

	if err := validatePiAgentConfigRefs(depFetchCtx, r, trigger.Namespace, trigger.Spec.Agent); err != nil {
		return nil, err
	}

	concurrency := normalizeConcurrency(trigger.Spec.Concurrency)
	resourceClient, err := getWatcherResourceClient(depFetchCtx, r, trigger.Namespace, r.DynamicClient.Resource(gvr), trigger.Spec.WatcherKubeconfigSecret, gvr)
	if err != nil {
		return nil, err
	}
	watchClients := buildWatchClients(resourceClient, trigger.Spec.Namespaces)
	deliveryGate := r.get(triggerRefName)
	jobCounter := sharedPiTriggerJobCounterRegistry.get(triggerRefName)
	maxJobs := int(trigger.Spec.MaxJobs)

	sessionLease, result, err := r.acquireSessionLease(reconcileCtx, reconcileLogger, triggerRefName, trigger)
	if err != nil || result != nil {
		return result, err
	}

	sessionTimeout := trigger.Spec.Timeout.Duration
	sessionCtx, sessionCancel := context.WithCancel(r.ctx)
	ctx := sessionCtx
	var timeoutCancel context.CancelFunc
	if sessionTimeout > 0 {
		remainingTimeout := time.Until(trigger.CreationTimestamp.Add(sessionTimeout))
		ctx, timeoutCancel = context.WithTimeout(sessionCtx, remainingTimeout)
	}

	var session *piTriggerSession
	var stopSessionOnce sync.Once
	stopSession := func() {
		stopSessionOnce.Do(func() {
			if timeoutCancel != nil {
				timeoutCancel()
			}
			sessionCancel()
			if session != nil && session.leaseRenewerDone != nil {
				select {
				case <-session.leaseRenewerDone:
				case <-time.After(2 * time.Second):
				}
			}
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer releaseCancel()
			if err := lease.ReleaseCoordinationLease(
				releaseCtx,
				r.Client,
				client.ObjectKey{Namespace: sessionLease.namespace, Name: sessionLease.name},
				sessionLease.holderIdentity,
			); err != nil {
				reconcileLogger.Error(err, "Trigger session lease release failed", "lease", sessionLease.name)
			}
		})
	}

	session = &piTriggerSession{stop: stopSession, sessionLease: sessionLease, leaseRenewerDone: make(chan struct{})}

	r.runningTriggersLock.Lock()
	if r.runningTriggers == nil {
		r.runningTriggers = map[string]func(){}
	}
	if r.runningTriggerSessions == nil {
		r.runningTriggerSessions = map[string]*piTriggerSession{}
	}
	r.runningTriggers[triggerRefName] = stopSession
	r.runningTriggerSessions[triggerRefName] = session
	r.runningTriggersLock.Unlock()
	recordControllerSessionStart(metricControllerPiTrigger)
	r.startSessionLeaseRenewer(ctx, reconcileLogger, triggerRefName, session)
	if r.DeletionWatcher != nil {
		r.DeletionWatcher.RegisterTask(triggerRefName, stopSession)
	}

	logger := reconcileLogger.WithValues("trigger", triggerRefName, "grv", gvr.String())
	triggerKey := client.ObjectKeyFromObject(trigger)
	triggerUID := trigger.UID
	triggerGeneration := trigger.Generation

	handleSessionTimeout := func() {
		logger.Info("Trigger session timed out", "timeout", sessionTimeout.String())

		deleteCtx, deleteCancel := context.WithTimeout(r.ctx, 10*time.Second)
		defer deleteCancel()

		latest := &triggersv1.PiTrigger{}
		if err := r.Get(deleteCtx, triggerKey, latest); err != nil {
			if !apierrors.IsNotFound(err) {
				logger.Error(err, "Timed out trigger fetch failed")
			}
		} else if latest.UID != triggerUID || latest.Generation != triggerGeneration {
			logger.V(1).Info("Skipping timed out trigger deletion for stale session", "uid", latest.UID, "generation", latest.Generation)
		} else if latest.GetDeletionTimestamp() == nil || latest.GetDeletionTimestamp().IsZero() {
			if err := r.dispatchTriggerSessionTimeoutJob(deleteCtx, triggerRefName, latest); err != nil {
				logger.Error(err, "Timed out trigger job dispatch failed")
			}
			if err := r.Delete(deleteCtx, latest); err != nil && !apierrors.IsNotFound(err) {
				logger.Error(err, "Timed out trigger deletion failed")
			}
		}

		r.runningTriggersLock.Lock()
		var stopFn func()
		if currentSession, ok := r.runningTriggerSessions[triggerRefName]; ok && currentSession == session {
			stopFn = r.detachRunningTriggerLocked(triggerRefName)
		}
		r.runningTriggersLock.Unlock()
		if stopFn != nil {
			stopFn()
		}
	}
	if sessionTimeout > 0 {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			handleSessionTimeout()
			return nil, nil
		}
		go func() {
			<-ctx.Done()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				handleSessionTimeout()
			}
		}()
	}

	listOpts := buildWatcherListOptions(resourceVersion, trigger.Spec.SendInitialEvents, trigger.Spec.LabelSelector, trigger.Spec.FieldSelector)
	watchers, err := openWatchers(ctx, watchClients, listOpts)
	if err != nil {
		r.stopRunningTrigger(triggerRefName)
		return nil, err
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
		const maxAttempts = 6
		var lastErr error
		for attempt := 0; attempt < maxAttempts; attempt++ {
			// Stop retrying if the controller or session context is cancelled
			if r.ctx.Err() != nil || ctx.Err() != nil {
				return
			}

			patchCtx, patchCancel := context.WithTimeout(r.ctx, time.Minute)
			latest := &triggersv1.PiTrigger{}
			if err := r.Get(patchCtx, triggerKey, latest); err != nil {
				patchCancel()
				// If the trigger was deleted, there's nothing to do.
				if apierrors.IsNotFound(err) {
					return
				}
				lastErr = err
				logger.Error(err, "Trigger fetch failed while recording runtime error", "attempt", attempt)
				// transient fetch error - retry after a short delay
				select {
				case <-time.After(time.Second):
					continue
				case <-ctx.Done():
					return
				}
			}
			patchCancel()

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

			patchCtx2, patchCancel2 := context.WithTimeout(r.ctx, time.Minute)
			err := r.Status().Patch(patchCtx2, patched, client.MergeFrom(latest))
			patchCancel2()
			if err == nil {
				return
			}
			if apierrors.IsNotFound(err) {
				return
			}
			lastErr = err
			logger.Error(err, "Trigger status update failed while recording runtime error", "attempt", attempt)

			// On transient errors (conflicts, etc.) retry with backoff
			if attempt < maxAttempts-1 {
				backoff := time.Second * time.Duration(1<<uint(attempt))
				if backoff > 8*time.Second {
					backoff = 8 * time.Second
				}
				select {
				case <-time.After(backoff):
					continue
				case <-ctx.Done():
					return
				}
			}
		}
		if lastErr != nil {
			logger.Error(lastErr, "Giving up recording runtime error after retries")
		}
	}

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

	return nil, nil
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

	return r.createPiWorkerJob(ctx, triggerRefName, trigger, eventPayload, metadataPayload)
}

func (r *PiTriggerReconciler) dispatchTriggerSessionTimeoutJob(ctx context.Context, triggerRefName string, trigger *triggersv1.PiTrigger) error {
	timedOutTrigger := trigger.DeepCopy()
	if timedOutTrigger.GetDeletionTimestamp() == nil || timedOutTrigger.GetDeletionTimestamp().IsZero() {
		timedOutTrigger.DeletionTimestamp = ptr.To(metav1.Now())
	}

	payload, err := runtime.DefaultUnstructuredConverter.ToUnstructured(timedOutTrigger)
	if err != nil {
		return err
	}

	const timeoutMessage = "trigger session timed out"
	rv := timedOutTrigger.GetResourceVersion()
	if rv == "" {
		rv = "0"
	}
	eventPayload := piTriggerEventInput{
		TriggerRefName:   triggerRefName,
		TriggerName:      timedOutTrigger.Name,
		TriggerNamespace: timedOutTrigger.Namespace,
		EventType:        string(triggersv1.EventTypeDeleted),
		ResourceVersion:  rv,
		Message:          timeoutMessage,
		Object:           payload,
	}
	metadataPayload := piTriggerJobMetadata{
		TriggerRefName:   triggerRefName,
		TriggerName:      timedOutTrigger.Name,
		TriggerNamespace: timedOutTrigger.Namespace,
		EventType:        string(triggersv1.EventTypeDeleted),
		ResourceVersion:  rv,
		Message:          timeoutMessage,
	}
	_, _, err = r.createPiWorkerJob(
		ctx,
		triggerRefName,
		timedOutTrigger,
		eventPayload,
		metadataPayload,
		"TIMED_OUT: The trigger session timed out. Use the payload and metadata to handle timeout cleanup for this deleted trigger.",
	)
	return err
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
	_, _, err = r.createPiWorkerJob(
		ctx,
		triggerRefName,
		trigger,
		eventPayload,
		metadataPayload,
		fmt.Sprintf("TIMED_OUT: The trigger owner lease %s timed out. Use the payload and metadata to handle timeout cleanup for this deleted trigger.", leaseName),
	)
	return err
}

func (r *PiTriggerReconciler) createPiWorkerJob(ctx context.Context, triggerRefName string, trigger *triggersv1.PiTrigger, eventPayload piTriggerEventInput, metadataPayload piTriggerJobMetadata, extraPromptSections ...string) (string, string, error) {
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

	// Session identity and fallback parsing
	sessionID, round, workerIndex := derivePiTriggerSessionIdentity(trigger)

	// capture restore-relevant annotations from the trigger
	sessionSecretName := strings.TrimSpace(trigger.GetAnnotations()[piTriggerSessionSecretAnnotation])
	outputLocation := strings.TrimSpace(trigger.GetAnnotations()[piTriggerOutputLocationAnnotation])
	traceID := buildPiTriggerTraceID(trigger, eventPayload)

	var nameHash string
	if sessionID != "" && round != "" && workerIndex != "" {
		nameHash = shortHash(strings.Join([]string{triggerRefName, eventPayload.EventType, objectNamespace, objectName, sessionID, round, workerIndex}, "|"))
	} else {
		nameHash = shortHash(strings.Join([]string{triggerRefName, eventPayload.EventType, objectNamespace, objectName, rv}, "|"))
	}
	jobName := buildPiTriggerResourceName(trigger.Name, nameHash, "job")
	if eventPayload.Message != "" {
		eventPayload.Message = buildPiTriggerTimeoutMessage(eventPayload.Message, triggerRefName, rv, jobName)
	}
	if metadataPayload.Message != "" {
		metadataPayload.Message = buildPiTriggerTimeoutMessage(metadataPayload.Message, triggerRefName, rv, jobName)
	}

	// enrich metadata with structured session/job identity for restore
	metadataPayload.SessionID = sessionID
	metadataPayload.Round = round
	metadataPayload.WorkerIndex = workerIndex
	metadataPayload.TraceID = traceID
	metadataPayload.SessionSecretName = sessionSecretName
	metadataPayload.JobName = jobName

	inputBase64, err := buildPiTriggerRuntimeInputEnvValue(eventPayload, metadataPayload)
	if err != nil {
		return "", "", err
	}
	subAgentDefaultsBase64, err := buildPiTriggerSubAgentDefaultsEnvValue(trigger.Namespace, traceID, trigger.Spec.Agent)
	if err != nil {
		return "", "", err
	}

	// build prompt (no error path)
	workerPrompt := buildRecoverablePiTriggerWorkerPrompt(trigger, jobName, extraPromptSections...)
	workerArgs := buildPiTriggerWorkerArgs(workerPrompt, trigger.Spec.Agent)
	activeDeadlineSeconds := resolvePiTriggerActiveDeadlineSeconds(trigger.Spec.Agent)
	ttlSecondsAfterFinished := resolvePiTriggerTTLSecondsAfterFinished(trigger.Spec.Agent)

	jobLabels, podLabels, jobAnnotations := buildPiWorkerLabelsAndAnnotations(trigger, traceID, sessionID, round, workerIndex, eventPayload.EventType, rv, sessionSecretName, outputLocation)

	job := assemblePiWorkerJob(trigger, jobName, jobLabels, podLabels, jobAnnotations, workerArgs, buildPiTriggerWorkerEnv(trigger.Spec.Agent.Env, inputBase64, subAgentDefaultsBase64), activeDeadlineSeconds, ttlSecondsAfterFinished)

	if err := r.setPiTriggerChildOwnerReference(ctx, trigger, job); err != nil {
		return "", "", err
	}
	if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		return "", "", err
	}

	return jobName, rv, nil
}

// derivePiTriggerSessionIdentity extracts session identity labels with fallback to parsing the trigger name
func derivePiTriggerSessionIdentity(trigger *triggersv1.PiTrigger) (string, string, string) {
	sessionID := strings.TrimSpace(trigger.GetLabels()[piTriggerSessionLabel])
	round := strings.TrimSpace(trigger.GetLabels()[piTriggerRoundLabel])
	workerIndex := strings.TrimSpace(trigger.GetLabels()[piTriggerWorkerLabel])
	if sessionID == "" || round == "" || workerIndex == "" {
		if dsid, dr, dw, ok := parsePiTriggerSessionIdentity(trigger.Name); ok {
			if sessionID == "" {
				sessionID = dsid
			}
			if round == "" {
				round = dr
			}
			if workerIndex == "" {
				workerIndex = dw
			}
		}
	}
	return sessionID, round, workerIndex
}

// buildPiWorkerLabelsAndAnnotations returns job labels, pod labels and job annotations
func buildPiWorkerLabelsAndAnnotations(trigger *triggersv1.PiTrigger, traceID, sessionID, round, workerIndex, eventType, rv, sessionSecretName, outputLocation string) (map[string]string, map[string]string, map[string]string) {
	jobLabels := map[string]string{
		piTriggerManagedLabel:     "true",
		piTriggerTriggerNameLabel: trigger.Name,
		piTriggerTraceIDLabel:     traceID,
	}
	if sessionID != "" {
		jobLabels[piTriggerSessionLabel] = sessionID
	}
	if round != "" {
		jobLabels[piTriggerRoundLabel] = round
	}
	if workerIndex != "" {
		jobLabels[piTriggerWorkerLabel] = workerIndex
	}
	jobAnnotations := map[string]string{
		piTriggerEventTypeAnnotation:       eventType,
		piTriggerResourceVersionAnnotation: rv,
	}
	if sessionSecretName != "" {
		jobAnnotations[piTriggerSessionSecretAnnotation] = sessionSecretName
	}
	if outputLocation != "" {
		jobAnnotations[piTriggerOutputLocationAnnotation] = outputLocation
	}
	podLabels := map[string]string{
		piTriggerManagedLabel:     "true",
		piTriggerTriggerNameLabel: trigger.Name,
		piTriggerTraceIDLabel:     traceID,
	}
	if sessionID != "" {
		podLabels[piTriggerSessionLabel] = sessionID
	}
	if round != "" {
		podLabels[piTriggerRoundLabel] = round
	}
	if workerIndex != "" {
		podLabels[piTriggerWorkerLabel] = workerIndex
	}
	return jobLabels, podLabels, jobAnnotations
}

// assemblePiWorkerJob constructs the Job object from pieces
func assemblePiWorkerJob(trigger *triggersv1.PiTrigger, jobName string, jobLabels, podLabels, jobAnnotations map[string]string, workerArgs []string, env []corev1.EnvVar, activeDeadlineSeconds *int64, ttlSecondsAfterFinished *int32) *batchv1.Job {
	// Build volumes and mounts: always include the required agent Secret, add optional ConfigMaps only when refs are provided
	agentSecretName := ""
	if trigger != nil {
		agentSecretName = trigger.Spec.Agent.ConfigSecretRef.Name
	}
	volumes := []corev1.Volume{{
		Name: piTriggerAgentSecretVolumeName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{SecretName: agentSecretName},
		},
	}}
	if trigger != nil && trigger.Spec.Agent.PromptsConfigMapRef != nil {
		volumes = append(volumes, corev1.Volume{
			Name: piTriggerPromptsVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: trigger.Spec.Agent.PromptsConfigMapRef.Name}},
			},
		})
	}
	if trigger != nil && trigger.Spec.Agent.SkillsConfigMapRef != nil {
		volumes = append(volumes, corev1.Volume{
			Name: piTriggerSkillsVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: trigger.Spec.Agent.SkillsConfigMapRef.Name}},
			},
		})
	}

	mounts := []corev1.VolumeMount{{
		Name:      piTriggerAgentSecretVolumeName,
		MountPath: piTriggerAgentConfigMountPath,
		ReadOnly:  true,
	}}
	if trigger != nil && trigger.Spec.Agent.PromptsConfigMapRef != nil {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      piTriggerPromptsVolumeName,
			MountPath: piTriggerAgentPromptsMountPath,
			ReadOnly:  true,
		})
	}
	if trigger != nil && trigger.Spec.Agent.SkillsConfigMapRef != nil {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      piTriggerSkillsVolumeName,
			MountPath: piTriggerAgentSkillsMountPath,
			ReadOnly:  true,
		})
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        jobName,
			Namespace:   trigger.Namespace,
			Labels:      jobLabels,
			Annotations: jobAnnotations,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            trigger.Spec.Agent.BackoffLimit,
			ActiveDeadlineSeconds:   activeDeadlineSeconds,
			TTLSecondsAfterFinished: ttlSecondsAfterFinished,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: podLabels,
				},
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyNever,
					ServiceAccountName: trigger.Spec.Agent.ServiceAccountName,
					// Volumes: always include the agent Secret, add optional ConfigMaps only when refs are provided
					Volumes: volumes,
					Containers: []corev1.Container{{
						Name:            piTriggerWorkerContainerName,
						Image:           trigger.Spec.Agent.Image,
						ImagePullPolicy: trigger.Spec.Agent.ImagePullPolicy,
						WorkingDir:      trigger.Spec.Agent.WorkingDir,
						Args:            workerArgs,
						Env:             env,
						EnvFrom:         trigger.Spec.Agent.EnvFrom,
						Resources:       trigger.Spec.Agent.Resources,
						// Mounts: match the volumes explicitly
						VolumeMounts: mounts,
					}},
				},
			},
		},
	}
}

func (r *PiTriggerReconciler) setPiTriggerChildOwnerReference(ctx context.Context, trigger *triggersv1.PiTrigger, child client.Object) error {
	if trigger == nil || child == nil {
		return nil
	}

	sessionSecretName := strings.TrimSpace(trigger.GetAnnotations()[piTriggerSessionSecretAnnotation])
	if sessionSecretName != "" {
		sessionSecret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: trigger.Namespace, Name: sessionSecretName}, sessionSecret); err != nil {
			return err
		}
		return controllerutil.SetControllerReference(sessionSecret, child, r.Scheme)
	}

	persistAfterTriggerDeletion := trigger.GetDeletionTimestamp() != nil && !trigger.GetDeletionTimestamp().IsZero()
	if persistAfterTriggerDeletion {
		return nil
	}

	return controllerutil.SetControllerReference(trigger, child, r.Scheme)
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

func buildPiTriggerTimeoutMessage(baseMessage, triggerRefName, resourceVersion, jobName string) string {
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
	return strings.Join(parts, "; ")
}

func buildRecoverablePiTriggerWorkerPrompt(trigger *triggersv1.PiTrigger, jobName string, extraSections ...string) string {
	sections := []string{}
	// Prepend user-defined agent prompt prefix when provided (trimmed and non-empty)
	if trigger != nil {
		if agentPrefix := strings.TrimSpace(trigger.Spec.Agent.Prompt); agentPrefix != "" {
			sections = append(sections, agentPrefix)
		}
	}
	if wakeupPrompt := buildPiTriggerWakeupPrompt(trigger, jobName); wakeupPrompt != "" {
		sections = append(sections, wakeupPrompt)
	}
	sections = append(sections,
		"Important: Before exiting for any reason, persist the wake-up/session state (Session ID, Round, Worker Index and any session metadata) to the configured session store, then call `exit_pi`; on timeout or failure ensure the process terminates with a non-zero exit code (do not continue without persisting).",
		"Task: Handle the triggering Kubernetes event using the mounted Pi agent configuration and the runtime PiTrigger skills; when performing timeout cleanup (TIMED_OUT) explicitly load the runtime input skill and the runtime diagnostics (job_status) for this worker Job, use those diagnostics to determine task failure and pod termination reason, create a Kubernetes Event owned by the triggered object describing the timeout and reason, and preserve the session Secret named in the runtime metadata (do NOT delete it) so that coordinated finalization/cleanup can occur later before calling `exit_pi`.",
		"The `pi-trigger-runtime-input` skill is generated by the runtime extension from the injected job environment and contains the decoded triggering object payload plus trigger metadata for this execution.",
		"The `pi-subagent-defaults-runtime` skill is generated from the injected PiTrigger agent defaults and should be used whenever this worker needs to create or hibernate sub-agents.",
		"Use those runtime skills as the source of truth instead of looking for mounted event.json or metadata.json files or a prompt-prefixed sub-agent defaults payload.",
	)
	sections = append(sections, extraSections...)
	sections = append(sections, "Load the runtime skills before acting so you can inspect the decoded triggering object payload, trigger metadata, and sub-agent defaults.")
	return strings.Join(sections, "\n\n")
}

func buildPiTriggerSubAgentDefaultsEnvValue(namespace, traceID string, agent triggersv1.PiAgentSpec) (string, error) {
	payload, err := json.Marshal(piTriggerSubAgentDefaults{Namespace: namespace, TraceID: traceID, Agent: agent})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(payload), nil
}

func buildPiTriggerTraceID(trigger *triggersv1.PiTrigger, eventPayload piTriggerEventInput) string {
	if trigger != nil {
		if traceID := strings.TrimSpace(trigger.GetLabels()[piTriggerTraceIDLabel]); traceID != "" {
			return traceID
		}
	}
	if metadata, ok := eventPayload.Object["metadata"].(map[string]interface{}); ok {
		if uid, ok := metadata["uid"].(string); ok && strings.TrimSpace(uid) != "" {
			return trimPiKubeLabelValue(fmt.Sprintf("%s-%d", uid, time.Now().Unix()), 63)
		}
	}
	if trigger != nil && strings.TrimSpace(trigger.Name) != "" {
		seed := trigger.Name
		if trigger.Namespace != "" {
			seed = trigger.Namespace + "-" + trigger.Name
		}
		return trimPiKubeLabelValue(fmt.Sprintf("%s-%d", seed, time.Now().Unix()), 63)
	}
	return trimPiKubeLabelValue(fmt.Sprintf("pi-%d", time.Now().Unix()), 63)
}

func buildPiTriggerRuntimeInputEnvValue(eventPayload piTriggerEventInput, metadataPayload piTriggerJobMetadata) (string, error) {
	payload, err := json.Marshal(piTriggerRuntimeInput{Payload: eventPayload.Object, Metadata: metadataPayload})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(payload), nil
}

func mergePiTriggerWorkerExtensions(extensions []string) []string {
	merged := make([]string, 0, len(extensions)+3)
	seen := map[string]struct{}{}
	for _, extension := range append([]string{piTriggerRuntimeExtensionPath, piTriggerTimeoutDiagnosticsExtensionPath, piTriggerServiceDiscoveryExtensionPath}, extensions...) {
		trimmed := strings.TrimSpace(extension)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		merged = append(merged, trimmed)
	}
	return merged
}

func buildPiTriggerWorkerEnv(agentEnv []corev1.EnvVar, inputBase64, subAgentDefaultsBase64 string) []corev1.EnvVar {
	env := make([]corev1.EnvVar, 0, len(agentEnv)+3)
	env = append(env, corev1.EnvVar{Name: "HOME", Value: piTriggerWorkerHomeDir})
	for _, candidate := range agentEnv {
		if candidate.Name == "HOME" || candidate.Name == piTriggerWorkerInputEnvVar || candidate.Name == piTriggerSubAgentDefaultsEnvVar {
			continue
		}
		env = append(env, candidate)
	}
	env = append(env,
		corev1.EnvVar{Name: piTriggerWorkerInputEnvVar, Value: inputBase64},
		corev1.EnvVar{Name: piTriggerSubAgentDefaultsEnvVar, Value: subAgentDefaultsBase64},
	)
	return env
}

func buildPiTriggerWakeupPrompt(trigger *triggersv1.PiTrigger, jobName string) string {
	if trigger == nil {
		return ""
	}

	sessionID := strings.TrimSpace(trigger.GetLabels()[piTriggerSessionLabel])
	round := strings.TrimSpace(trigger.GetLabels()[piTriggerRoundLabel])
	workerIndex := strings.TrimSpace(trigger.GetLabels()[piTriggerWorkerLabel])
	if derivedSessionID, derivedRound, derivedWorkerIndex, ok := parsePiTriggerSessionIdentity(trigger.Name); ok {
		if sessionID == "" {
			sessionID = derivedSessionID
		}
		if round == "" {
			round = derivedRound
		}
		if workerIndex == "" {
			workerIndex = derivedWorkerIndex
		}
	}
	if sessionID == "" || round == "" || workerIndex == "" {
		return ""
	}

	lines := []string{
		fmt.Sprintf("Session ID: %s", sessionID),
		fmt.Sprintf("Namespace: %s", trigger.Namespace),
		fmt.Sprintf("Session Secret Label: %s=%s", piTriggerSessionLabel, sessionID),
		fmt.Sprintf("Round: %s", round),
		fmt.Sprintf("Worker Index: %s", workerIndex),
	}
	if jobName != "" {
		lines = append(lines, fmt.Sprintf("Job: %s", jobName))
	}
	return strings.Join(lines, "\n")
}

func parsePiTriggerSessionIdentity(triggerName string) (string, string, string, bool) {
	trimmed := strings.TrimSpace(triggerName)
	// Try the newer pi-session-<rand8>-<sessionId>-r<round>-w<worker>-trigger format first
	if matches := piTriggerSessionTriggerNamePatternV2.FindStringSubmatch(trimmed); len(matches) == 4 {
		return matches[1], matches[2], matches[3], true
	}
	// Fallback to legacy pi-subagent-<sessionId>-r<round>-w<worker>-trigger format
	if matches := piTriggerSessionTriggerNamePattern.FindStringSubmatch(trimmed); len(matches) == 4 {
		return matches[1], matches[2], matches[3], true
	}
	return "", "", "", false
}

func buildPiTriggerWorkerArgs(prompt string, agent triggersv1.PiAgentSpec) []string {
	args := []string{"--mode", "json"}
	if agent.NoExtensions {
		args = append(args, "--no-extensions")
	}
	for _, extension := range mergePiTriggerWorkerExtensions(agent.Extensions) {
		args = append(args, "--extension", extension)
	}
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

func resolvePiTriggerTTLSecondsAfterFinished(agent triggersv1.PiAgentSpec) *int32 {
	if agent.TTLSecondsAfterFinished != nil {
		return agent.TTLSecondsAfterFinished
	}
	return ptr.To(int32(86400))
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

	// PromptsConfigMapRef and SkillsConfigMapRef are optional pointers; only validate them if present.
	if agent.PromptsConfigMapRef != nil {
		if strings.TrimSpace(agent.PromptsConfigMapRef.Name) == "" {
			return errors.Join(ErrInvalidTriggerContent, errors.New("agent.promptsConfigMapRef.name is required"))
		}
	}
	if agent.SkillsConfigMapRef != nil {
		if strings.TrimSpace(agent.SkillsConfigMapRef.Name) == "" {
			return errors.Join(ErrInvalidTriggerContent, errors.New("agent.skillsConfigMapRef.name is required"))
		}
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

	// Only attempt to look up ConfigMaps that were actually provided (non-nil refs).
	refs := map[string]string{}
	if agent.PromptsConfigMapRef != nil {
		refs["agent.promptsConfigMapRef.name"] = agent.PromptsConfigMapRef.Name
	}
	if agent.SkillsConfigMapRef != nil {
		refs["agent.skillsConfigMapRef.name"] = agent.SkillsConfigMapRef.Name
	}

	for fieldName, configMapName := range refs {
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

func trimPiKubeLabelValue(value string, maxLength int) string {
	lowered := strings.ToLower(value)
	replaced := strings.NewReplacer("_", "-", "/", "-", ":", "-", " ", "-").Replace(lowered)
	filtered := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			return r
		}
		return '-'
	}, replaced)
	collapsed := regexp.MustCompile(`-+`).ReplaceAllString(filtered, "-")
	trimmed := strings.Trim(collapsed, "-.")
	if maxLength > 0 && len(trimmed) > maxLength {
		trimmed = strings.Trim(trimmed[:maxLength], "-.")
	}
	if trimmed == "" {
		return "pi"
	}
	return trimmed
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
		initResult, initErr := r.createTrigger(ctx, logf.FromContext(ctx).WithValues("controller", "pitrigger", "name", refName), refName, &trigger)
		triggerMu.Unlock()
		if initErr != nil {
			r.runningTriggersLock.Lock()
			stopFns := make([]func(), 0, len(r.runningTriggers))
			for runningRef := range r.runningTriggers {
				if stopFn := r.detachRunningTriggerLocked(runningRef); stopFn != nil {
					stopFns = append(stopFns, stopFn)
				}
			}
			r.runningTriggersLock.Unlock()
			for _, stopFn := range stopFns {
				stopFn()
			}
			return initErr
		}
		if initResult != nil {
			continue
		}
	}

	return nil
}

func (r *PiTriggerReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager, maxConcurrentReconciles int, wg *sync.WaitGroup) error {
	r.ctx = ctx
	r.Recorder = mgr.GetEventRecorderFor("pitrigger-controller")
	r.runningTriggersLock = sync.Mutex{}
	r.runningTriggers = map[string]func(){}
	r.runningTriggerSessions = map[string]*piTriggerSession{}
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
		stopFns := make([]func(), 0, len(r.runningTriggers))
		for refName := range r.runningTriggers {
			if stopFn := r.detachRunningTriggerLocked(refName); stopFn != nil {
				stopFns = append(stopFns, stopFn)
			}
		}
		r.runningTriggersLock.Unlock()
		for _, stopFn := range stopFns {
			stopFn()
		}

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
				r.runningTriggerSessions = map[string]*piTriggerSession{}
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
