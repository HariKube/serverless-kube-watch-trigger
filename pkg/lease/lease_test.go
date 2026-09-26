package lease

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type conflictPatchClient struct {
	client.Client
}

func (c conflictPatchClient) Patch(
	_ context.Context,
	obj client.Object,
	_ client.Patch,
	_ ...client.PatchOption,
) error {
	groupResource := schema.GroupResource{
		Group:    "",
		Resource: "configmaps",
	}

	return apierrors.NewConflict(
		groupResource,
		obj.GetName(),
		errors.New("conflict"),
	)
}

func TestResolveDurationPrefersOverride(t *testing.T) {
	t.Parallel()

	resolved := ResolveDuration(5*time.Second, 30*time.Second)
	if resolved != 5*time.Second {
		t.Fatalf("expected override duration to win, got %s", resolved)
	}
}

func TestResolveDurationFallsBackToDefault(t *testing.T) {
	t.Parallel()

	resolved := ResolveDuration(0, 0)
	if resolved != DefaultLockDuration {
		t.Fatalf("expected default lock duration, got %s", resolved)
	}
}

func TestTryAcquireLeaseAcquiresAndWritesAnnotation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"}}
	cl := fake.NewClientBuilder().WithObjects(cm).Build()

	result, err := TryAcquireLease(ctx, cl, cm, now, 30*time.Second)
	if err != nil {
		t.Fatalf("TryAcquireLease returned error: %v", err)
	}
	if !result.Acquired {
		t.Fatalf("expected lease to be acquired, got %#v", result)
	}
	if result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}
	if result.Conflict {
		t.Fatalf("expected no conflict, got %#v", result)
	}

	updated := &corev1.ConfigMap{}
	if err := cl.Get(ctx, client.ObjectKeyFromObject(cm), updated); err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if got := updated.Annotations[AnnotationKey]; got != now.Format(time.RFC3339) {
		t.Fatalf("expected annotation %q, got %q", now.Format(time.RFC3339), got)
	}
}

func TestTryAcquireLeaseReturnsRemainingDurationForActiveLease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 20, 0, time.UTC)
	lockedAt := now.Add(-10 * time.Second)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name:      "test",
		Namespace: "default",
		Annotations: map[string]string{
			AnnotationKey: lockedAt.Format(time.RFC3339),
		},
	}}
	cl := fake.NewClientBuilder().WithObjects(cm).Build()

	result, err := TryAcquireLease(ctx, cl, cm, now, 30*time.Second)
	if err != nil {
		t.Fatalf("TryAcquireLease returned error: %v", err)
	}
	if result.Acquired {
		t.Fatalf("expected lease acquisition to be skipped, got %#v", result)
	}
	if result.Conflict {
		t.Fatalf("expected no conflict, got %#v", result)
	}
	if result.RequeueAfter != 20*time.Second {
		t.Fatalf("expected requeue after 20s, got %s", result.RequeueAfter)
	}
}

func TestActiveLeaseRemainingReturnsZeroWhenExpired(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 2, 3, 4, 20, 0, time.UTC)
	lockedAt := now.Add(-10 * time.Second)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{
			AnnotationKey: lockedAt.Format(time.RFC3339),
		},
	}}

	if got := ActiveLeaseRemaining(cm, now, 5*time.Second); got != 0 {
		t.Fatalf("expected expired lease to report zero remaining duration, got %s", got)
	}
}

func TestTryAcquireLeaseReportsConflict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"}}
	baseClient := fake.NewClientBuilder().WithObjects(cm).Build()
	cl := conflictPatchClient{Client: baseClient}

	result, err := TryAcquireLease(ctx, cl, cm, now, 30*time.Second)
	if err != nil {
		t.Fatalf("TryAcquireLease returned error: %v", err)
	}
	if result.Acquired {
		t.Fatalf("expected lease acquisition to fail, got %#v", result)
	}
	if !result.Conflict {
		t.Fatalf("expected conflict result, got %#v", result)
	}
	if result.RequeueAfter != 0 {
		t.Fatalf("expected no explicit requeue duration, got %s", result.RequeueAfter)
	}
}

func TestClearLeaseRemovesAnnotation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name:      "test",
		Namespace: "default",
		Annotations: map[string]string{
			AnnotationKey:                        time.Now().UTC().Format(time.RFC3339),
			"triggers.harikube.info/other-state": "kept",
		},
	}}
	cl := fake.NewClientBuilder().WithObjects(cm).Build()

	if err := ClearLease(ctx, cl, cm); err != nil {
		t.Fatalf("ClearLease returned error: %v", err)
	}

	updated := &corev1.ConfigMap{}
	if err := cl.Get(ctx, client.ObjectKeyFromObject(cm), updated); err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if _, ok := updated.Annotations[AnnotationKey]; ok {
		t.Fatalf("expected lock annotation to be removed, got %#v", updated.Annotations)
	}
	if got := updated.Annotations["triggers.harikube.info/other-state"]; got != "kept" {
		t.Fatalf("expected unrelated annotation to remain, got %#v", updated.Annotations)
	}
}
