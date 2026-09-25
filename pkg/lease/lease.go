package lease

import (
	"context"
	"math/rand/v2"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	AnnotationKey       = "triggers.harikube.info/lock-timestamp"
	DefaultLockDuration = 30 * time.Second
)

type TryAcquireResult struct {
	Acquired     bool
	Conflict     bool
	RequeueAfter time.Duration
}

func ResolveDuration(override, fallback time.Duration) time.Duration {
	if override > 0 {
		return override
	}
	return NormalizeDuration(fallback)
}

func NormalizeDuration(lockDuration time.Duration) time.Duration {
	if lockDuration <= 0 {
		return DefaultLockDuration
	}
	return lockDuration
}

func ConflictRetryDelay() time.Duration {
	return time.Second + time.Duration(rand.IntN(1000))*time.Millisecond
}

func TryAcquireLease(
	ctx context.Context,
	cl client.Client,
	obj client.Object,
	now time.Time,
	lockDuration time.Duration,
) (TryAcquireResult, error) {
	lockDuration = NormalizeDuration(lockDuration)
	latest := obj.DeepCopyObject().(client.Object)
	if err := cl.Get(ctx, client.ObjectKeyFromObject(obj), latest); err != nil {
		return TryAcquireResult{}, err
	}

	if requeueAfter := activeLeaseRemaining(latest, now, lockDuration); requeueAfter > 0 {
		return TryAcquireResult{RequeueAfter: requeueAfter}, nil
	}

	patched := latest.DeepCopyObject().(client.Object)
	annotations := copyAnnotations(latest.GetAnnotations())
	annotations[AnnotationKey] = now.UTC().Format(time.RFC3339)
	patched.SetAnnotations(annotations)

	patch := client.MergeFromWithOptions(
		latest,
		client.MergeFromWithOptimisticLock{},
	)
	if err := cl.Patch(ctx, patched, patch); err != nil {
		if apierrors.IsConflict(err) {
			return TryAcquireResult{Conflict: true}, nil
		}
		return TryAcquireResult{}, err
	}

	obj.SetAnnotations(patched.GetAnnotations())
	obj.SetResourceVersion(patched.GetResourceVersion())

	return TryAcquireResult{Acquired: true}, nil
}

func ClearLease(ctx context.Context, cl client.Client, obj client.Object) error {
	latest := obj.DeepCopyObject().(client.Object)
	if err := cl.Get(ctx, client.ObjectKeyFromObject(obj), latest); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	annotations := latest.GetAnnotations()
	if len(annotations) == 0 {
		return nil
	}
	if _, ok := annotations[AnnotationKey]; !ok {
		return nil
	}

	patched := latest.DeepCopyObject().(client.Object)
	nextAnnotations := copyAnnotations(annotations)
	delete(nextAnnotations, AnnotationKey)
	if len(nextAnnotations) == 0 {
		nextAnnotations = nil
	}
	patched.SetAnnotations(nextAnnotations)

	patch := client.MergeFromWithOptions(
		latest,
		client.MergeFromWithOptimisticLock{},
	)
	if err := cl.Patch(ctx, patched, patch); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	obj.SetAnnotations(patched.GetAnnotations())
	obj.SetResourceVersion(patched.GetResourceVersion())

	return nil
}

func activeLeaseRemaining(obj client.Object, now time.Time, lockDuration time.Duration) time.Duration {
	ts := obj.GetAnnotations()[AnnotationKey]
	if ts == "" {
		return 0
	}

	lockedAt, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0
	}

	elapsed := now.UTC().Sub(lockedAt.UTC())
	if elapsed < 0 {
		elapsed = 0
	}
	if elapsed >= lockDuration {
		return 0
	}

	return lockDuration - elapsed
}

func copyAnnotations(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}

	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
