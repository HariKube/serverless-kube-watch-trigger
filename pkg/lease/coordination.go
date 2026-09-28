package lease

import (
	"context"
	"fmt"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CoordinationAcquireResult struct {
	Acquired     bool
	RequeueAfter time.Duration
}

func TryAcquireCoordinationLease(
	ctx context.Context,
	cl client.Client,
	key client.ObjectKey,
	holderIdentity string,
	now time.Time,
	leaseDuration time.Duration,
) (CoordinationAcquireResult, error) {
	leaseDuration = NormalizeDuration(leaseDuration)
	leaseDurationSeconds := durationSeconds(leaseDuration)

	for attempt := 0; attempt < 3; attempt++ {
		current := &coordinationv1.Lease{}
		err := cl.Get(ctx, key, current)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return CoordinationAcquireResult{}, err
			}

			created := &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: coordinationv1.LeaseSpec{
					HolderIdentity:       &holderIdentity,
					LeaseDurationSeconds: &leaseDurationSeconds,
					AcquireTime:          microTime(now),
					RenewTime:            microTime(now),
				},
			}
			if createErr := cl.Create(ctx, created); createErr != nil {
				if apierrors.IsAlreadyExists(createErr) || apierrors.IsConflict(createErr) {
					continue
				}
				return CoordinationAcquireResult{}, createErr
			}
			return CoordinationAcquireResult{Acquired: true}, nil
		}

		if holderIdentityEqual(current, holderIdentity) {
			patched := current.DeepCopy()
			patched.Spec.HolderIdentity = &holderIdentity
			patched.Spec.LeaseDurationSeconds = &leaseDurationSeconds
			patched.Spec.RenewTime = microTime(now)
			if patched.Spec.AcquireTime == nil {
				patched.Spec.AcquireTime = microTime(now)
			}
			patch := client.MergeFromWithOptions(
				current,
				client.MergeFromWithOptimisticLock{},
			)
			if err := cl.Patch(ctx, patched, patch); err != nil {
				if apierrors.IsConflict(err) {
					continue
				}
				return CoordinationAcquireResult{}, err
			}
			return CoordinationAcquireResult{Acquired: true}, nil
		}

		if requeueAfter := CoordinationLeaseRemaining(current, now); requeueAfter > 0 {
			return CoordinationAcquireResult{RequeueAfter: requeueAfter}, nil
		}

		patched := current.DeepCopy()
		patched.Spec.HolderIdentity = &holderIdentity
		patched.Spec.LeaseDurationSeconds = &leaseDurationSeconds
		patched.Spec.AcquireTime = microTime(now)
		patched.Spec.RenewTime = microTime(now)
		transitions := int32(1)
		if current.Spec.LeaseTransitions != nil {
			transitions = *current.Spec.LeaseTransitions + 1
		}
		patched.Spec.LeaseTransitions = &transitions
		patch := client.MergeFromWithOptions(
			current,
			client.MergeFromWithOptimisticLock{},
		)
		if err := cl.Patch(ctx, patched, patch); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return CoordinationAcquireResult{}, err
		}
		return CoordinationAcquireResult{Acquired: true}, nil
	}

	return CoordinationAcquireResult{}, fmt.Errorf(
		"failed to acquire coordination lease %s/%s after retries",
		key.Namespace,
		key.Name,
	)
}

func RenewCoordinationLease(
	ctx context.Context,
	cl client.Client,
	key client.ObjectKey,
	holderIdentity string,
	now time.Time,
	leaseDuration time.Duration,
) (bool, error) {
	leaseDuration = NormalizeDuration(leaseDuration)
	leaseDurationSeconds := durationSeconds(leaseDuration)

	for attempt := 0; attempt < 3; attempt++ {
		current := &coordinationv1.Lease{}
		if err := cl.Get(ctx, key, current); err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		if !holderIdentityEqual(current, holderIdentity) {
			return false, nil
		}

		patched := current.DeepCopy()
		patched.Spec.HolderIdentity = &holderIdentity
		patched.Spec.LeaseDurationSeconds = &leaseDurationSeconds
		patched.Spec.RenewTime = microTime(now)
		if patched.Spec.AcquireTime == nil {
			patched.Spec.AcquireTime = microTime(now)
		}
		patch := client.MergeFromWithOptions(
			current,
			client.MergeFromWithOptimisticLock{},
		)
		if err := cl.Patch(ctx, patched, patch); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return false, err
		}
		return true, nil
	}

	return false, fmt.Errorf(
		"failed to renew coordination lease %s/%s after retries",
		key.Namespace,
		key.Name,
	)
}

func ReleaseCoordinationLease(
	ctx context.Context,
	cl client.Client,
	key client.ObjectKey,
	holderIdentity string,
) error {
	for attempt := 0; attempt < 3; attempt++ {
		current := &coordinationv1.Lease{}
		if err := cl.Get(ctx, key, current); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		if !holderIdentityEqual(current, holderIdentity) {
			return nil
		}

		patched := current.DeepCopy()
		patched.Spec.HolderIdentity = nil
		patched.Spec.AcquireTime = nil
		patched.Spec.RenewTime = nil
		patch := client.MergeFromWithOptions(
			current,
			client.MergeFromWithOptimisticLock{},
		)
		if err := cl.Patch(ctx, patched, patch); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		return nil
	}

	return fmt.Errorf(
		"failed to release coordination lease %s/%s after retries",
		key.Namespace,
		key.Name,
	)
}

// CoordinationLeaseRemaining reports how long the current holder still owns the
// lease. A lease that nobody holds is never reported as remaining: session
// leases are cleared (holder, acquireTime and renewTime all nil) on release, and
// a freshly created lease is not held until the first acquisition patches it.
// Falling back to creationTimestamp here would make a released or never-acquired
// lease look held for its whole duration, which would make an update reconcile
// tear down the live session and then sit idle until the lease expired.
func CoordinationLeaseRemaining(obj *coordinationv1.Lease, now time.Time) time.Duration {
	if obj == nil || obj.Spec.HolderIdentity == nil || *obj.Spec.HolderIdentity == "" {
		return 0
	}
	if obj.Spec.LeaseDurationSeconds == nil || *obj.Spec.LeaseDurationSeconds <= 0 {
		return 0
	}

	var renewedAt time.Time
	switch {
	case obj.Spec.RenewTime != nil && !obj.Spec.RenewTime.Time.IsZero():
		renewedAt = obj.Spec.RenewTime.Time
	case obj.Spec.AcquireTime != nil && !obj.Spec.AcquireTime.Time.IsZero():
		renewedAt = obj.Spec.AcquireTime.Time
	default:
		// Held but without a timestamp to measure from; do not block the
		// acquisition, the caller patches a fresh acquire/renew time anyway.
		return 0
	}

	expiresAt := renewedAt.UTC().Add(time.Duration(*obj.Spec.LeaseDurationSeconds) * time.Second)
	remaining := expiresAt.Sub(now.UTC())
	if remaining <= 0 {
		return 0
	}
	return remaining
}

func holderIdentityEqual(obj *coordinationv1.Lease, holderIdentity string) bool {
	return obj.Spec.HolderIdentity != nil && *obj.Spec.HolderIdentity == holderIdentity
}

func durationSeconds(duration time.Duration) int32 {
	seconds := int32(duration / time.Second)
	if duration%time.Second != 0 {
		seconds++
	}
	if seconds <= 0 {
		seconds = int32(DefaultLockDuration / time.Second)
	}
	return seconds
}

func microTime(now time.Time) *metav1.MicroTime {
	mt := metav1.NewMicroTime(now.UTC())
	return &mt
}
