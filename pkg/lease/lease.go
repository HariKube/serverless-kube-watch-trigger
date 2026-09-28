package lease

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	AnnotationKey       = "triggers.harikube.info/lock-timestamp"
	DefaultLockDuration = 30 * time.Second
)

// Annotation lease patches use an optimistic lock, so they can collide with the
// controller's own status writes. Retry a few times before giving up so a stale
// cache read does not turn into a spurious release failure.
const (
	leasePatchAttempts   = 5
	leasePatchRetryDelay = 50 * time.Millisecond
)

func sleepContext(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

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

func ActiveLeaseRemaining(obj client.Object, now time.Time, lockDuration time.Duration) time.Duration {
	return activeLeaseRemaining(obj, now, NormalizeDuration(lockDuration))
}

// TryAcquireLease claims the annotation lease for obj. Reads go through cl,
// which may be backed by an informer cache, so a concurrent write (for example
// the status write of the very reconcile that claims the lease) can make the
// optimistic-lock patch fail with a conflict on stale data. Such conflicts are
// retried a few times before the caller is asked to back off.
func TryAcquireLease(
	ctx context.Context,
	cl client.Client,
	obj client.Object,
	now time.Time,
	lockDuration time.Duration,
) (TryAcquireResult, error) {
	lockDuration = NormalizeDuration(lockDuration)

	for attempt := 0; attempt < leasePatchAttempts; attempt++ {
		latest := obj.DeepCopyObject().(client.Object)
		if err := cl.Get(ctx, client.ObjectKeyFromObject(obj), latest); err != nil {
			return TryAcquireResult{}, err
		}

		if requeueAfter := ActiveLeaseRemaining(latest, now, lockDuration); requeueAfter > 0 {
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
				if attempt+1 < leasePatchAttempts {
					sleepContext(ctx, leasePatchRetryDelay)
				}
				continue
			}
			return TryAcquireResult{}, err
		}

		obj.SetAnnotations(patched.GetAnnotations())
		obj.SetResourceVersion(patched.GetResourceVersion())

		return TryAcquireResult{Acquired: true}, nil
	}

	return TryAcquireResult{Conflict: true}, nil
}

// ClearLease releases the annotation lease held on obj. Like TryAcquireLease it
// retries optimistic-lock conflicts caused by reading through a possibly stale
// cache instead of surfacing them as errors.
func ClearLease(ctx context.Context, cl client.Client, obj client.Object) error {
	for attempt := 0; attempt < leasePatchAttempts; attempt++ {
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
			if apierrors.IsConflict(err) {
				if attempt+1 < leasePatchAttempts {
					sleepContext(ctx, leasePatchRetryDelay)
				}
				continue
			}
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}

		obj.SetAnnotations(patched.GetAnnotations())
		obj.SetResourceVersion(patched.GetResourceVersion())

		return nil
	}

	return fmt.Errorf("failed to release annotation lease %s/%s after retries", obj.GetNamespace(), obj.GetName())
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
