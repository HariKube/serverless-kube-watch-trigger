package lease

import (
	"context"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newLeaseTestClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := coordinationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme returned error: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func TestTryAcquireCoordinationLeaseCreatesLease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cl := newLeaseTestClient(t)
	key := client.ObjectKey{Namespace: "default", Name: "session"}

	result, err := TryAcquireCoordinationLease(
		ctx,
		cl,
		key,
		"pod-a/httptrigger/abc",
		now,
		15*time.Second,
	)
	if err != nil {
		t.Fatalf("TryAcquireCoordinationLease returned error: %v", err)
	}
	if !result.Acquired {
		t.Fatalf("expected lease to be acquired, got %#v", result)
	}

	leaseObj := &coordinationv1.Lease{}
	if err := cl.Get(ctx, key, leaseObj); err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if leaseObj.Spec.HolderIdentity == nil || *leaseObj.Spec.HolderIdentity != "pod-a/httptrigger/abc" {
		t.Fatalf("expected holder identity to be written, got %#v", leaseObj.Spec.HolderIdentity)
	}
}

func TestTryAcquireCoordinationLeaseReturnsRemainingDurationForActiveLease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 20, 0, time.UTC)
	leaseObj := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "default"},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       ptrString("pod-a/httptrigger/abc"),
			LeaseDurationSeconds: ptrInt32(30),
			RenewTime:            ptrMicroTime(now.Add(-10 * time.Second)),
		},
	}
	cl := newLeaseTestClient(t, leaseObj)

	result, err := TryAcquireCoordinationLease(
		ctx,
		cl,
		client.ObjectKeyFromObject(leaseObj),
		"pod-b/httptrigger/def",
		now,
		30*time.Second,
	)
	if err != nil {
		t.Fatalf("TryAcquireCoordinationLease returned error: %v", err)
	}
	if result.Acquired {
		t.Fatalf("expected lease acquisition to be skipped, got %#v", result)
	}
	if result.RequeueAfter != 20*time.Second {
		t.Fatalf("expected requeue after 20s, got %s", result.RequeueAfter)
	}
}

func TestRenewCoordinationLeaseReturnsFalseForDifferentHolder(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 20, 0, time.UTC)
	leaseObj := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "default"},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       ptrString("pod-a/httptrigger/abc"),
			LeaseDurationSeconds: ptrInt32(30),
			RenewTime:            ptrMicroTime(now.Add(-10 * time.Second)),
		},
	}
	cl := newLeaseTestClient(t, leaseObj)

	renewed, err := RenewCoordinationLease(
		ctx,
		cl,
		client.ObjectKeyFromObject(leaseObj),
		"pod-b/httptrigger/def",
		now,
		30*time.Second,
	)
	if err != nil {
		t.Fatalf("RenewCoordinationLease returned error: %v", err)
	}
	if renewed {
		t.Fatal("expected renew to fail for a different holder")
	}
}

func TestReleaseCoordinationLeaseClearsHolderForCurrentOwner(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 20, 0, time.UTC)
	leaseObj := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "default"},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       ptrString("pod-a/httptrigger/abc"),
			LeaseDurationSeconds: ptrInt32(30),
			RenewTime:            ptrMicroTime(now.Add(-10 * time.Second)),
		},
	}
	cl := newLeaseTestClient(t, leaseObj)

	err := ReleaseCoordinationLease(
		ctx,
		cl,
		client.ObjectKeyFromObject(leaseObj),
		"pod-a/httptrigger/abc",
	)
	if err != nil {
		t.Fatalf("ReleaseCoordinationLease returned error: %v", err)
	}

	updated := &coordinationv1.Lease{}
	if err := cl.Get(ctx, client.ObjectKeyFromObject(leaseObj), updated); err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if updated.Spec.HolderIdentity != nil {
		t.Fatalf("expected holder identity to be cleared, got %#v", updated.Spec.HolderIdentity)
	}
}

// A session lease that nobody holds must not be reported as still valid, even
// when creationTimestamp is recent. Otherwise an update reconcile releases the
// old session, immediately re-acquires for the same trigger and is told to wait
// out the full lock duration with no watcher running.
func TestCoordinationLeaseRemainingIgnoresUnheldLease(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 2, 3, 4, 20, 0, time.UTC)
	leaseObj := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "session",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(now.Add(-time.Second)),
		},
		Spec: coordinationv1.LeaseSpec{LeaseDurationSeconds: ptrInt32(30)},
	}

	if got := CoordinationLeaseRemaining(leaseObj, now); got != 0 {
		t.Fatalf("expected unheld lease to report no remaining time, got %s", got)
	}
}

// Reproduces the trigger update path: the controller stops the old session,
// which releases the lease, and then starts the new session for the same
// pod+trigger (the holder identity is deterministic, so it is unchanged).
// That acquisition must succeed right away.
func TestTryAcquireCoordinationLeaseSucceedsAfterSameHolderRelease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	key := client.ObjectKey{Namespace: "default", Name: "session"}
	holder := "pod-a/httptrigger/abc"

	// A real API server stamps creationTimestamp; the fake client does not.
	cl := newLeaseTestClient(t, &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:              key.Name,
			Namespace:         key.Namespace,
			CreationTimestamp: metav1.NewTime(now),
		},
		Spec: coordinationv1.LeaseSpec{LeaseDurationSeconds: ptrInt32(30)},
	})

	if result, err := TryAcquireCoordinationLease(ctx, cl, key, holder, now, 30*time.Second); err != nil {
		t.Fatalf("initial acquire returned error: %v", err)
	} else if !result.Acquired {
		t.Fatalf("initial acquire did not succeed: %#v", result)
	}

	if err := ReleaseCoordinationLease(ctx, cl, key, holder); err != nil {
		t.Fatalf("ReleaseCoordinationLease returned error: %v", err)
	}

	later := now.Add(3 * time.Second)
	result, err := TryAcquireCoordinationLease(ctx, cl, key, holder, later, 30*time.Second)
	if err != nil {
		t.Fatalf("TryAcquireCoordinationLease after release returned error: %v", err)
	}
	if !result.Acquired {
		t.Fatalf("expected the released lease to be re-acquirable, got %#v", result)
	}
}

// Another replica holding an unexpired lease must still be respected.
func TestTryAcquireCoordinationLeaseRespectsActiveForeignLease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 20, 0, time.UTC)
	leaseObj := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "session",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(now.Add(-time.Minute)),
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       ptrString("pod-a/httptrigger/abc"),
			LeaseDurationSeconds: ptrInt32(30),
			RenewTime:            ptrMicroTime(now.Add(-10 * time.Second)),
		},
	}
	cl := newLeaseTestClient(t, leaseObj)

	result, err := TryAcquireCoordinationLease(
		ctx,
		cl,
		client.ObjectKeyFromObject(leaseObj),
		"pod-b/httptrigger/def",
		now,
		30*time.Second,
	)
	if err != nil {
		t.Fatalf("TryAcquireCoordinationLease returned error: %v", err)
	}
	if result.Acquired {
		t.Fatalf("expected acquisition to be blocked by the active foreign lease, got %#v", result)
	}
	if result.RequeueAfter != 20*time.Second {
		t.Fatalf("expected requeue after 20s, got %s", result.RequeueAfter)
	}
}

func ptrString(value string) *string { return &value }
func ptrInt32(value int32) *int32    { return &value }
func ptrMicroTime(value time.Time) *metav1.MicroTime {
	mt := metav1.NewMicroTime(value)
	return &mt
}
