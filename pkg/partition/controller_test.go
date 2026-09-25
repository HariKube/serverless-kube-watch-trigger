package partition

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestSingleWorkerOwnsAllDistributions(t *testing.T) {
	controller := NewSingleWorkerController()
	for i := 1; i <= TotalPartitions; i++ {
		if !controller.OwnsDistribution(partitionName(i)) {
			t.Fatalf("expected single-worker controller to own %s", partitionName(i))
		}
	}
}

func TestDistributedRefreshClaimsQuotaAndPrunesStaleEntries(t *testing.T) {
	now := time.Now().UTC()
	clientset := k8sfake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultConfigMapName, Namespace: "operators"},
		Data: map[string]string{
			heartbeatKey("pod-b"):          now.Format(time.RFC3339),
			heartbeatKey("pod-stale"):      now.Add(-10 * time.Minute).Format(time.RFC3339),
			partitionKey(partitionName(1)): "pod-b",
			partitionKey(partitionName(2)): "pod-stale",
		},
	})

	controller := NewDistributedController(clientset, "operators", "pod-a")
	if err := controller.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	owned := controller.OwnedPartitions()
	if len(owned) != 50 {
		t.Fatalf("expected 50 owned partitions with two active replicas, got %d", len(owned))
	}
	foundReclaimed := false
	for _, partition := range owned {
		if partition == partitionName(2) {
			foundReclaimed = true
			break
		}
	}
	if !foundReclaimed {
		t.Fatalf("expected reclaimed partition %s to be owned, got %#v", partitionName(2), owned)
	}

	cm, err := clientset.CoreV1().ConfigMaps("operators").Get(
		context.Background(),
		DefaultConfigMapName,
		metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("get configmap: %v", err)
	}
	if _, exists := cm.Data[heartbeatKey("pod-stale")]; exists {
		t.Fatal("expected stale heartbeat to be removed")
	}
	if owner := cm.Data[partitionKey(partitionName(2))]; owner != "pod-a" {
		t.Fatalf("expected stale partition to be reassigned to pod-a, got %q", owner)
	}
}

func TestOwnsObjectUsesDistributionLabelInDistributedMode(t *testing.T) {
	controller := NewDistributedController(k8sfake.NewSimpleClientset(), "operators", "pod-a")
	controller.setOwnedPartitions([]string{"item-7"})

	owned := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{DistributionLabelKey: "item-7"}}}
	if !controller.OwnsObject(owned) {
		t.Fatal("expected object with owned distribution label to be accepted")
	}

	unowned := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{DistributionLabelKey: "item-8"}}}
	if controller.OwnsObject(unowned) {
		t.Fatal("expected object with unowned distribution label to be rejected")
	}
}

func TestDistributedControllerOptionsKeepDeadmanAboveRefreshPeriod(t *testing.T) {
	controller := NewDistributedControllerWithOptions(
		k8sfake.NewSimpleClientset(),
		"operators",
		"pod-a",
		Options{ClaimRefreshInterval: 7 * time.Minute},
	)

	if controller.claimRefreshInterval != 7*time.Minute {
		t.Fatalf("expected custom refresh period to be used, got %s", controller.claimRefreshInterval)
	}
	if controller.deadmanTimeout <= controller.claimRefreshInterval {
		t.Fatalf(
			"expected deadman timeout %s to be greater than refresh period %s",
			controller.deadmanTimeout,
			controller.claimRefreshInterval,
		)
	}
}

func TestDistributedControllerHonorsExplicitDeadmanTimeoutWhenSafe(t *testing.T) {
	controller := NewDistributedControllerWithOptions(
		k8sfake.NewSimpleClientset(),
		"operators",
		"pod-a",
		Options{
			ClaimRefreshInterval: 2 * time.Minute,
			DeadmanTimeout:       3 * time.Minute,
		},
	)

	if controller.deadmanTimeout != 3*time.Minute {
		t.Fatalf("expected explicit deadman timeout to be preserved, got %s", controller.deadmanTimeout)
	}
}
