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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"

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
	"github.com/harikube/serverless-kube-watch-trigger/pkg/lease"
	"github.com/harikube/serverless-kube-watch-trigger/pkg/partition"
	triggerwatcher "github.com/harikube/serverless-kube-watch-trigger/pkg/watcher"
)

var ErrInvalidTriggerContent = errors.New("invalid trigger content")

type watchInitializer interface {
	WatchInit(ctx context.Context) error
}

type Watcher struct {
	Initializer watchInitializer
}

func (w *Watcher) Start(ctx context.Context) error {
	return w.Initializer.WatchInit(ctx)
}

// HTTPTriggerReconciler reconciles a HTTPTrigger object
type HTTPTriggerReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	DynamicClient *dynamic.DynamicClient
	Recorder      record.EventRecorder

	PartitionController *partition.Controller
	DeletionWatcher     *triggerwatcher.GlobalDeletionWatcher

	deliveryGateRegistry

	ctx                    context.Context
	runningTriggersLock    sync.Mutex
	runningTriggers        map[string]func()
	runningTriggerSessions map[string]*httpTriggerSession

	triggerLocksLock sync.Mutex
	triggerLocks     map[string]*sync.Mutex
}

type httpTriggerSession struct {
	stop             func()
	sessionLease     triggerSessionLease
	leaseRenewerDone chan struct{}
}

// triggerLock returns the mutex that serializes reconcile work (session
// creation, update and deletion) for a single trigger so a trigger can never
// end up with more than one live watcher session. Reconciles for different
// triggers hold different locks and therefore run in parallel instead of
// serializing on the shared runningTriggersLock.
func (r *HTTPTriggerReconciler) triggerLock(triggerRefName string) *sync.Mutex {
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
func (r *HTTPTriggerReconciler) stopRunningTrigger(triggerRefName string) {
	r.runningTriggersLock.Lock()
	stopFn := r.detachRunningTriggerLocked(triggerRefName)
	r.runningTriggersLock.Unlock()

	if stopFn != nil {
		stopFn()
	}
}

// detachRunningTriggerLocked removes the watcher session bookkeeping for a trigger and
// returns the stop function that must be invoked after releasing runningTriggersLock.
func (r *HTTPTriggerReconciler) detachRunningTriggerLocked(triggerRefName string) func() {
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
		recordControllerSessionStop(metricControllerHTTPTrigger)
	}
	if r.DeletionWatcher != nil {
		r.DeletionWatcher.UnregisterTask(triggerRefName)
	}
	return stopFn
}

// +kubebuilder:rbac:groups=triggers.harikube.info,resources=httptriggers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=httptriggers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=httptriggers/finalizers,verbs=update
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups="",resources=secrets;services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch;update

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
	recordReconcileStart(metricControllerHTTPTrigger)
	defer recordReconcileDone(metricControllerHTTPTrigger)

	logger := logf.FromContext(ctx).WithValues("controller", "httptrigger", "name", req.NamespacedName)
	triggerRefName := req.String()

	// Serialize reconcile work per trigger (never globally) so a trigger's
	// watcher session is created/updated/deleted atomically while triggers
	// reconcile against each other in parallel.
	triggerMu := r.triggerLock(triggerRefName)
	triggerMu.Lock()
	defer triggerMu.Unlock()

	trigger := triggersv1.HTTPTrigger{}
	if err := r.Get(ctx, req.NamespacedName, &trigger); err != nil {
		if apierrors.IsNotFound(err) {
			// The trigger was deleted without a finalizer and is already gone.
			// Make sure its watcher session is cancelled and the map entry is
			// removed so it cannot keep delivering events as a zombie.
			r.stopRunningTrigger(triggerRefName)
			r.remove(triggerRefName)
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
	// by another replica keeps its current watcher instead of going dark until
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

	recoveryRestart := !trigger.Status.ErrorTime.IsZero() &&
		trigger.Status.LastGeneration == trigger.Generation

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

func (r *HTTPTriggerReconciler) preflightReconcile(ctx context.Context, logger logr.Logger, triggerRefName string, trigger *triggersv1.HTTPTrigger) (bool, error) {
	if trigger.DeletionTimestamp != nil || !trigger.DeletionTimestamp.IsZero() {
		logger.Info("Trigger deleted")
		if err := r.deliverOwnerLeaseTimeoutCallback(ctx, logger, triggerRefName, trigger); err != nil {
			logger.Error(err, "Trigger deletion timeout callback failed")
		}
		r.stopRunningTrigger(triggerRefName)
		r.remove(triggerRefName)
		return true, nil
	}
	if r.PartitionController != nil && !r.PartitionController.OwnsObject(trigger) {
		r.stopRunningTrigger(triggerRefName)
		r.remove(triggerRefName)
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
func (r *HTTPTriggerReconciler) clearExpiredAnnotationLease(ctx context.Context, logger logr.Logger, trigger *triggersv1.HTTPTrigger) error {
	return clearExpiredAnnotationLease(ctx, logger, r.Client, trigger, trigger.Spec.LockDuration.Duration)
}

func (r *HTTPTriggerReconciler) acquireSessionLease(ctx context.Context, logger logr.Logger, triggerRefName string, trigger *triggersv1.HTTPTrigger) (triggerSessionLease, *ctrl.Result, error) {
	sessionLease := newTriggerSessionLease("httptrigger", trigger, triggerRefName, trigger.Spec.LockDuration.Duration)
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

func (r *HTTPTriggerReconciler) startSessionLeaseRenewer(ctx context.Context, logger logr.Logger, triggerRefName string, session *httpTriggerSession) {
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

func (r *HTTPTriggerReconciler) deliverOwnerLeaseTimeoutCallback(ctx context.Context, logger logr.Logger, triggerRefName string, trigger *triggersv1.HTTPTrigger) error {
	leaseName, ok, err := r.expiredOwnerLeaseName(ctx, trigger, time.Now().UTC())
	if err != nil {
		return err
	}

	timeoutMessage := "trigger session timed out"
	if ok {
		timeoutMessage = fmt.Sprintf("owner lease %s timed out", leaseName)
	}
	payload, err := runtime.DefaultUnstructuredConverter.ToUnstructured(trigger.DeepCopy())
	if err != nil {
		return err
	}
	payload["message"] = timeoutMessage
	payload["eventType"] = string(triggersv1.EventTypeDeleted)
	if ok {
		payload["timedOutLease"] = map[string]interface{}{"name": leaseName}
	}

	compiledTemplates := map[string]*template.Template{}
	if err := compileSharedTemplates(compiledTemplates, "", trigger.Spec.URL, trigger.Spec.Headers); err != nil {
		return err
	}
	if trigger.Spec.Body.Template != "" {
		if err := addCompiledTemplate(compiledTemplates, "body_template", trigger.Spec.Body.Template, template.FuncMap{"toJson": toJson}); err != nil {
			return errors.Join(err, ErrInvalidTriggerContent, errors.New("failed to parse body template"))
		}
	}

	depFetchCtx, depFetchCancel := context.WithTimeout(ctx, time.Minute)
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

	var signature []byte
	if trigger.Spec.Body.Signature.KeySecretRef.Name != "" {
		signature, err = loadSecretBytes(depFetchCtx, r, trigger.Namespace, trigger.Spec.Body.Signature.KeySecretRef)
		if err != nil {
			return err
		}
	}

	httpClient, err := newTriggerHTTPClient(depFetchCtx, r, trigger.Namespace, trigger.Spec.Auth.TLS, trigger.Spec.Delivery.Timeout.Duration, normalizeConcurrency(trigger.Spec.Concurrency))
	if err != nil {
		return err
	}

	url, err := buildTriggerURL(trigger.Spec.URL, compiledTemplates, payload, serviceScheme, servicePort)
	if err != nil {
		return err
	}

	body := toJson(map[string]string{"message": timeoutMessage})
	if trigger.Spec.Body.Template != "" {
		body, err = renderTemplateToString(compiledTemplates, "body_template", payload)
		if err != nil {
			return err
		}
	}

	contentType := trigger.Spec.Body.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	headers, err := buildTriggerHeaders(contentType, trigger.Spec.Headers, headerSecrets, compiledTemplates, payload)
	if err != nil {
		return err
	}
	if trigger.Spec.Body.Signature.HMAC != nil {
		var hashFunc func() hash.Hash
		switch trigger.Spec.Body.Signature.HMAC.HashType {
		case triggersv1.SignatureHashTypeSHA256:
			hashFunc = sha256.New
		case triggersv1.SignatureHashTypeSHA512:
			hashFunc = sha512.New
		}

		hasher := hmac.New(hashFunc, signature)
		_, _ = hasher.Write([]byte(body))
		headers[trigger.Spec.Body.Signature.Header] = hex.EncodeToString(hasher.Sum(nil))
	}

	metadata, _ := payload["metadata"].(map[string]interface{})
	if metadata == nil {
		metadata = map[string]interface{}{
			"name":            trigger.Name,
			"namespace":       trigger.Namespace,
			"resourceVersion": trigger.ResourceVersion,
		}
	}

	_, err = deliverPayload(
		ctx,
		logger,
		httpClient,
		triggerRefName,
		methodOrDefault(trigger.Spec.Method),
		url,
		body,
		headers,
		trigger.Spec.Auth.BasicAuth,
		userAuthPassword,
		trigger.Spec.Delivery.Retries,
		trigger.Spec.Delivery.Timeout.Duration,
		retryBackoff{min: defaultRetryBackoffMin, max: defaultRetryBackoffMax},
		string(triggersv1.EventTypeDeleted),
		metadata,
	)
	return err
}

func (r *HTTPTriggerReconciler) expiredOwnerLeaseName(ctx context.Context, trigger *triggersv1.HTTPTrigger, now time.Time) (string, bool, error) {
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

func leaseTimedOut(ownerLease *coordinationv1.Lease, now time.Time) bool {
	if ownerLease == nil || ownerLease.Spec.LeaseDurationSeconds == nil || *ownerLease.Spec.LeaseDurationSeconds <= 0 {
		return false
	}

	var renewedAt time.Time
	switch {
	case ownerLease.Spec.RenewTime != nil && !ownerLease.Spec.RenewTime.Time.IsZero():
		renewedAt = ownerLease.Spec.RenewTime.Time
	case ownerLease.Spec.AcquireTime != nil && !ownerLease.Spec.AcquireTime.Time.IsZero():
		renewedAt = ownerLease.Spec.AcquireTime.Time
	case !ownerLease.CreationTimestamp.IsZero():
		renewedAt = ownerLease.CreationTimestamp.Time
	default:
		return false
	}

	expiresAt := renewedAt.Add(time.Duration(*ownerLease.Spec.LeaseDurationSeconds) * time.Second)
	return !expiresAt.After(now)
}

//nolint:gocyclo
func (r *HTTPTriggerReconciler) createTrigger(reconcileCtx context.Context, reconcileLogger logr.Logger, triggerRefName string, trigger *triggersv1.HTTPTrigger) (*ctrl.Result, error) {
	resourceVersion := triggerResourceVersion(trigger.Status.ErrorResourceVersion)
	gvr, gvk := buildTriggerResourceInfo(trigger.Spec.Resource)
	eventTypes := buildTriggerEventTypes(trigger.Spec.EventType)

	compiledTemplates := map[string]*template.Template{}
	if err := compileSharedTemplates(compiledTemplates, trigger.Spec.EventFilter, trigger.Spec.URL, trigger.Spec.Headers); err != nil {
		return nil, err
	}
	if trigger.Spec.Body.Template != "" {
		if err := addCompiledTemplate(compiledTemplates, "body_template", trigger.Spec.Body.Template, template.FuncMap{"toJson": toJson}); err != nil {
			return nil, errors.Join(err, ErrInvalidTriggerContent, errors.New("failed to parse body template"))
		}
	}

	depFetchCtx, depFetchCancel := context.WithTimeout(r.ctx, time.Minute)
	defer depFetchCancel()

	serviceScheme, servicePort, err := resolveServiceEndpoint(depFetchCtx, r, trigger.Spec.URL.Service)
	if err != nil {
		return nil, err
	}

	var userAuthPassword string
	if trigger.Spec.Auth.BasicAuth != nil {
		userAuthPassword, err = loadSecretString(depFetchCtx, r, trigger.Namespace, trigger.Spec.Auth.BasicAuth.PasswordRef)
		if err != nil {
			return nil, err
		}
	}

	headerSecrets, err := loadHeaderSecrets(depFetchCtx, r, trigger.Namespace, trigger.Spec.Headers.FromSecretRef)
	if err != nil {
		return nil, err
	}

	var signature []byte
	if trigger.Spec.Body.Signature.KeySecretRef.Name != "" {
		signature, err = loadSecretBytes(depFetchCtx, r, trigger.Namespace, trigger.Spec.Body.Signature.KeySecretRef)
		if err != nil {
			return nil, err
		}
	}

	concurrency := normalizeConcurrency(trigger.Spec.Concurrency)
	httpClient, err := newTriggerHTTPClient(depFetchCtx, r, trigger.Namespace, trigger.Spec.Auth.TLS, trigger.Spec.Delivery.Timeout.Duration, concurrency)
	if err != nil {
		return nil, err
	}

	resourceClient, err := getWatcherResourceClient(depFetchCtx, r, trigger.Namespace, r.DynamicClient.Resource(gvr), trigger.Spec.WatcherKubeconfigSecret, gvr)
	if err != nil {
		return nil, err
	}
	watchClients := buildWatchClients(resourceClient, trigger.Spec.Namespaces)

	sessionLease, result, err := r.acquireSessionLease(reconcileCtx, reconcileLogger, triggerRefName, trigger)
	if err != nil || result != nil {
		return result, err
	}

	sessionTimeout := trigger.Spec.Timeout.Duration
	sessionCtx, sessionCancel := context.WithCancel(r.ctx)
	ctx := sessionCtx
	var timeoutCancel context.CancelFunc
	if sessionTimeout > 0 {
		ctx, timeoutCancel = context.WithTimeout(sessionCtx, sessionTimeout)
	}

	var session *httpTriggerSession
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

	session = &httpTriggerSession{stop: stopSession, sessionLease: sessionLease, leaseRenewerDone: make(chan struct{})}

	r.runningTriggersLock.Lock()
	if r.runningTriggers == nil {
		r.runningTriggers = map[string]func(){}
	}
	if r.runningTriggerSessions == nil {
		r.runningTriggerSessions = map[string]*httpTriggerSession{}
	}
	r.runningTriggers[triggerRefName] = stopSession
	r.runningTriggerSessions[triggerRefName] = session
	r.runningTriggersLock.Unlock()
	recordControllerSessionStart(metricControllerHTTPTrigger)
	r.startSessionLeaseRenewer(ctx, reconcileLogger, triggerRefName, session)
	if r.DeletionWatcher != nil {
		r.DeletionWatcher.RegisterTask(triggerRefName, stopSession)
	}

	triggerKey := client.ObjectKeyFromObject(trigger)
	triggerUID := trigger.UID
	triggerGeneration := trigger.Generation

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

	recordRuntimeError := func(errorReason, errorResourceVersion string) {
		patchCtx, patchCancel := context.WithTimeout(r.ctx, time.Minute)
		defer patchCancel()

		latest := &triggersv1.HTTPTrigger{}
		if err := r.Get(patchCtx, client.ObjectKeyFromObject(trigger), latest); err != nil {
			return
		}
		if latest.Generation != trigger.Generation {
			return
		}

		// Always refresh ErrorTime so repeated identical runtime delivery
		// failures still advance status.errorTime; only update reason/resourceVersion
		// and phase when they have changed so the recovery semantics remain intact.
		patched := latest.DeepCopy()
		patched.Status.ErrorTime = metav1.Now()
		if latest.Status.Phase != triggersv1.TriggerPhaseError || latest.Status.ErrorReason != errorReason || latest.Status.ErrorResourceVersion != errorResourceVersion {
			patched.Status.ErrorReason = errorReason
			patched.Status.ErrorResourceVersion = errorResourceVersion
			patched.Status.Phase = triggersv1.TriggerPhaseError
		}
		_ = r.Status().Patch(patchCtx, patched, client.MergeFrom(latest))
	}

	logger := reconcileLogger.WithValues("trigger", triggerRefName, "grv", gvr.String())
	if sessionTimeout > 0 {
		go func(session *httpTriggerSession) {
			<-ctx.Done()
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return
			}

			logger.Info("Trigger session timed out", "timeout", sessionTimeout.String())

			deleteCtx, deleteCancel := context.WithTimeout(r.ctx, 10*time.Second)
			defer deleteCancel()

			latest := &triggersv1.HTTPTrigger{}
			if err := r.Get(deleteCtx, triggerKey, latest); err != nil {
				if !apierrors.IsNotFound(err) {
					logger.Error(err, "Timed out trigger fetch failed")
				}
			} else if latest.UID != triggerUID || latest.Generation != triggerGeneration {
				logger.V(1).Info("Skipping timed out trigger deletion for stale session", "uid", latest.UID, "generation", latest.Generation)
			} else if latest.GetDeletionTimestamp() == nil || latest.GetDeletionTimestamp().IsZero() {
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
		}(session)
	}

	logger.Info("Watcher started")

	const (
		minReconnectBackoff = time.Second
		maxReconnectBackoff = 30 * time.Second
	)

	deliveryGate := r.get(triggerRefName)

	for i := 1; i <= int(trigger.Spec.Concurrency); i++ {
		recordWatcherGoroutineStart(metricControllerHTTPTrigger)
		go func() {
			defer recordWatcherGoroutineDone(metricControllerHTTPTrigger)
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
						logger.Error(errors.New("failed to convert bookmark to metav1.PartialObjectMetadata"), "Skipping malformed bookmark event")
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

				for {
					url, err := buildTriggerURL(trigger.Spec.URL, compiledTemplates, unstructuredObj.Object, serviceScheme, servicePort)
					if err != nil {
						logger.Error(err, "Skipping watch event because URL build failed", "eventType", event.Type, "resourceVersion", unstructuredObj.GetResourceVersion(), "name", metadata["name"], "namespace", metadata["namespace"])
						break
					}

					body := ""
					if trigger.Spec.Body.Template != "" {
						body, err = renderTemplateToString(compiledTemplates, "body_template", unstructuredObj.Object)
						if err != nil {
							logger.Error(err, "Skipping watch event because body template rendering failed", "eventType", event.Type, "resourceVersion", unstructuredObj.GetResourceVersion(), "name", metadata["name"], "namespace", metadata["namespace"])
							break
						}
					}

					contentType := "application/json"
					if trigger.Spec.Body.ContentType != "" {
						contentType = trigger.Spec.Body.ContentType
					}
					headers, err := buildTriggerHeaders(contentType, trigger.Spec.Headers, headerSecrets, compiledTemplates, unstructuredObj.Object)
					if err != nil {
						logger.Error(err, "Skipping watch event because header rendering failed", "eventType", event.Type, "resourceVersion", unstructuredObj.GetResourceVersion(), "name", metadata["name"], "namespace", metadata["namespace"])
						break
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
						_, _ = hasher.Write([]byte(body))
						signatureBytes := hasher.Sum(nil)
						headers[trigger.Spec.Body.Signature.Header] = hex.EncodeToString(signatureBytes)
					}

					if delay := deliveryGate.delay(); delay > 0 {
						recordDeliveryBackoff(kindHTTPTrigger, triggerRefName)
						logger.V(1).Info("Delaying delivery due to sustained endpoint failure", "name", metadata["name"], "namespace", metadata["namespace"], "delay", delay.String(), "consecutiveFailures", deliveryGate.consecutiveFailures())
						if !sleepContext(ctx, delay) {
							return
						}
					}

					ok, retryErr := deliverPayload(
						ctx,
						logger,
						httpClient,
						triggerRefName,
						methodOrDefault(trigger.Spec.Method),
						url,
						body,
						headers,
						trigger.Spec.Auth.BasicAuth,
						userAuthPassword,
						trigger.Spec.Delivery.Retries,
						trigger.Spec.Delivery.Timeout.Duration,
						retryBackoff{min: defaultRetryBackoffMin, max: defaultRetryBackoffMax},
						string(event.Type),
						metadata,
					)
					if ok {
						deliveryGate.recordSuccess()
						for {
							rv, ok := metadata["resourceVersion"].(string)
							if !ok || rv == "" {
								logger.Error(fmt.Errorf("object metadata.resourceVersion is missing or invalid"), "Skipping resourceVersion checkpoint update after successful delivery", "eventType", event.Type, "name", metadata["name"], "namespace", metadata["namespace"])
								break
							}
							lrv := lastResourceVersion.Load()
							if natsort.Compare(rv, *lrv) {
								break
							} else if lastResourceVersion.CompareAndSwap(lrv, &rv) {
								break
							}
						}
						break
					}

					deliveryGate.recordFailure()
					emitTriggerCallFailureEvent(r.Recorder, trigger, triggerRefName, methodOrDefault(trigger.Spec.Method), url, event.Type, metadata, retryErr)
					recordRuntimeError(fmt.Sprintf("retry failed: %v", retryErr), unstructuredObj.GetResourceVersion())
					retryDelay := deliveryGate.delay()
					if retryDelay <= 0 {
						retryDelay = time.Second
					}
					logger.Error(retryErr, "HTTP trigger delivery failed, retrying", "name", metadata["name"], "namespace", metadata["namespace"], "resourceVersion", unstructuredObj.GetResourceVersion(), "retryAfter", retryDelay.String())
					if !sleepContext(ctx, retryDelay) {
						return
					}
					continue
				}
			}
		}()
	}

	return nil, nil
}

func (r *HTTPTriggerReconciler) WatchInit(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	existingTriggers := triggersv1.HTTPTriggerList{}
	if err := r.List(ctx, &existingTriggers); err != nil {
		return err
	}

	for _, trigger := range existingTriggers.Items {
		refName := trigger.Namespace + "/" + trigger.Name
		if r.PartitionController != nil && !r.PartitionController.OwnsObject(&trigger) {
			r.stopRunningTrigger(refName)
			r.remove(refName)
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
		initResult, initErr := r.createTrigger(ctx, logf.FromContext(ctx).WithValues("controller", "httptrigger", "name", refName), refName, &trigger)
		triggerMu.Unlock()

		if initErr != nil {
			// Cancel every session started so far: a partially-initialized
			// operator must not leave zombie watchers behind.
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

// SetupWithManager sets up the controller with the Manager.
func (r *HTTPTriggerReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager, maxConcurrentReconciles int, wg *sync.WaitGroup) error {
	r.ctx = ctx
	r.Recorder = mgr.GetEventRecorderFor("httptrigger-controller")
	r.init()
	r.runningTriggersLock = sync.Mutex{}
	r.runningTriggers = map[string]func(){}
	r.runningTriggerSessions = map[string]*httpTriggerSession{}
	r.triggerLocksLock = sync.Mutex{}
	r.triggerLocks = map[string]*sync.Mutex{}
	if r.DeletionWatcher == nil {
		r.DeletionWatcher = triggerwatcher.NewGlobalDeletionWatcher()
	}
	if r.PartitionController == nil {
		r.PartitionController = partition.NewSingleWorkerController()
	}
	if informer, err := mgr.GetCache().GetInformer(ctx, &triggersv1.HTTPTrigger{}); err != nil {
		return err
	} else if err := r.DeletionWatcher.Start(ctx, informer); err != nil {
		return err
	}
	if r.PartitionController.Mode() == partition.ModeDistributedPartition {
		r.PartitionController.AddChangeListener(func(listenerCtx context.Context) {
			if err := r.WatchInit(listenerCtx); err != nil {
				logf.FromContext(listenerCtx).Error(err, "distributed HTTPTrigger resync failed")
			}
		})
	}

	recordControllerRegistered(metricControllerHTTPTrigger)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer recordControllerStopped(metricControllerHTTPTrigger)

		<-ctx.Done()

		r.clear()

		// Cancel every running watcher session and remove its map entry so the
		// goroutines watching it can terminate promptly.
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
				r.runningTriggerSessions = map[string]*httpTriggerSession{}
				r.runningTriggersLock.Unlock()

				return
			}

			time.Sleep(50 * time.Millisecond)
		}
	}()

	return ctrl.NewControllerManagedBy(mgr).
		For(&triggersv1.HTTPTrigger{}).
		Named("httptrigger").
		WithOptions(controller.Options{
			NeedLeaderElection:      ptr.To(true),
			MaxConcurrentReconciles: maxConcurrentReconciles,
			RecoverPanic:            ptr.To(true),
			Logger:                  mgr.GetLogger(),
		}).
		Complete(r)
}
