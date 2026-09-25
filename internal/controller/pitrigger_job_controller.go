package controller

import (
	"context"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
)

// PiTriggerJobReconciler updates PiTrigger status from spawned worker Jobs.
type PiTriggerJobReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=pitriggers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=delete;get

func (r *PiTriggerJobReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	recordReconcileStart(metricControllerPiTriggerJob)
	defer recordReconcileDone(metricControllerPiTriggerJob)

	logger := logf.FromContext(ctx).WithValues("controller", "pitrigger-job", "job", req.NamespacedName)

	job := &batchv1.Job{}
	if err := r.Get(ctx, req.NamespacedName, job); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if job.Labels[piTriggerManagedLabel] != "true" {
		return ctrl.Result{}, nil
	}

	triggerName := job.Labels[piTriggerTriggerNameLabel]
	if triggerName == "" {
		return ctrl.Result{}, nil
	}

	failed, terminal, reason := derivePiJobResult(job)
	if !terminal {
		return ctrl.Result{}, nil
	}

	sharedPiTriggerJobCounterRegistry.get(job.Namespace + "/" + triggerName).releaseTerminalJob(job)

	trigger := &triggersv1.PiTrigger{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: job.Namespace, Name: triggerName}, trigger); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if failed {
		latest := trigger.DeepCopy()
		updated := latest.DeepCopy()
		newErrorReason := fmt.Sprintf("pi worker job %s failed: %s", job.Name, reason)
		newErrorRV := job.Annotations[piTriggerResourceVersionAnnotation]
		if updated.Status.ErrorReason != newErrorReason || updated.Status.ErrorResourceVersion != newErrorRV {
			updated.Status.ErrorReason = newErrorReason
			updated.Status.ErrorTime = metav1.Now()
			updated.Status.ErrorResourceVersion = newErrorRV

			if err := r.Status().Patch(ctx, updated, client.MergeFrom(latest)); err != nil {
				if apierrors.IsNotFound(err) {
					return ctrl.Result{}, nil
				}
				logger.Error(err, "Trigger status update failed")
				return ctrl.Result{}, err
			}
		}
	}

	if terminal {
		if configMapName := job.Annotations[piTriggerInputConfigMapAnnotation]; configMapName != "" {
			cm := &corev1.ConfigMap{}
			err := r.Get(ctx, client.ObjectKey{Namespace: job.Namespace, Name: configMapName}, cm)
			if err == nil {
				if delErr := r.Delete(ctx, cm); delErr != nil && !apierrors.IsNotFound(delErr) {
					return ctrl.Result{}, delErr
				}
			} else if !apierrors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

func derivePiJobResult(job *batchv1.Job) (failed bool, terminal bool, reason string) {
	for _, condition := range job.Status.Conditions {
		if condition.Status != corev1.ConditionTrue {
			continue
		}
		switch condition.Type {
		case batchv1.JobComplete:
			return false, true, condition.Reason
		case batchv1.JobFailed:
			reason := condition.Message
			if reason == "" {
				reason = condition.Reason
			}
			return true, true, reason
		}
	}
	return false, false, ""
}

func (r *PiTriggerJobReconciler) SetupWithManager(mgr ctrl.Manager) error {
	recordControllerRegistered(metricControllerPiTriggerJob)
	labelSelector, err := predicate.LabelSelectorPredicate(metav1.LabelSelector{
		MatchLabels: map[string]string{
			piTriggerManagedLabel: "true",
		},
	})
	if err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}, builder.WithPredicates(labelSelector)).
		Named("pitrigger-job").
		WithOptions(controller.Options{
			NeedLeaderElection: ptr.To(true),
			RecoverPanic:       ptr.To(true),
			Logger:             mgr.GetLogger(),
		}).
		Complete(r)
}
