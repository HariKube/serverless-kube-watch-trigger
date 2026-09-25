package partition

import (
	"context"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestConfigMapWatcherWipeConfigMapRemovesOnlyCurrentPodEntries(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultConfigMapName, Namespace: "operators"},
		Data: map[string]string{
			heartbeatKey("pod-a"):          time.Now().UTC().Format(time.RFC3339),
			heartbeatKey("pod-b"):          time.Now().UTC().Format(time.RFC3339),
			partitionKey(partitionName(1)): "pod-a",
			partitionKey(partitionName(2)): "pod-b",
		},
	})

	watcher := NewConfigMapWatcher(clientset, "operators", DefaultConfigMapName, "pod-a", nil)
	watcher.WipeConfigMap(context.Background())

	cm, err := clientset.CoreV1().ConfigMaps("operators").Get(
		context.Background(),
		DefaultConfigMapName,
		metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("get configmap: %v", err)
	}
	if _, exists := cm.Data[heartbeatKey("pod-a")]; exists {
		t.Fatal("expected current pod heartbeat to be removed")
	}
	if _, exists := cm.Data[partitionKey(partitionName(1))]; exists {
		t.Fatal("expected current pod partition claim to be removed")
	}
	if owner := cm.Data[partitionKey(partitionName(2))]; owner != "pod-b" {
		t.Fatalf("expected other pod claim to be preserved, got %q", owner)
	}
}

func TestConfigMapWatcherStartWipesClaimsOnSignal(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultConfigMapName, Namespace: "operators"},
		Data: map[string]string{
			heartbeatKey("pod-a"):          time.Now().UTC().Format(time.RFC3339),
			partitionKey(partitionName(1)): "pod-a",
		},
	})

	signalCh := make(chan os.Signal, 1)
	watcher := NewConfigMapWatcher(clientset, "operators", DefaultConfigMapName, "pod-a", nil)
	watcher.signalChan = signalCh
	watcher.retryDelay = 10 * time.Millisecond
	watcher.deadmanTimeout = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Start(ctx)

	signalCh <- os.Interrupt
	time.Sleep(100 * time.Millisecond)

	cm, err := clientset.CoreV1().ConfigMaps("operators").Get(
		context.Background(),
		DefaultConfigMapName,
		metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("get configmap: %v", err)
	}
	if len(cm.Data) != 0 {
		t.Fatalf("expected signal-triggered wipe to remove current pod entries, got %#v", cm.Data)
	}
}
