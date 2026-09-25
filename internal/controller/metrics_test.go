package controller

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktypes "k8s.io/apimachinery/pkg/types"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
)

func TestRuntimeMetricsTrackControllerAndWatcherActivity(t *testing.T) {
	resetRuntimeMetricsForTesting()

	recordControllerRegistered(metricControllerHTTPTrigger)
	if got := testutil.ToFloat64(controllersRunning.WithLabelValues(metricControllerHTTPTrigger)); got != 1 {
		t.Fatalf("expected registered controller gauge to be 1, got %v", got)
	}

	recordControllerSessionStart(metricControllerHTTPTrigger)
	recordControllerSessionStart(metricControllerHTTPTrigger)
	if got := testutil.ToFloat64(controllersRunning.WithLabelValues(metricControllerHTTPTrigger)); got != 3 {
		t.Fatalf("expected controller/session gauge to be 3, got %v", got)
	}

	recordControllerSessionStop(metricControllerHTTPTrigger)
	if got := testutil.ToFloat64(controllersRunning.WithLabelValues(metricControllerHTTPTrigger)); got != 2 {
		t.Fatalf("expected controller/session gauge to be 2 after stop, got %v", got)
	}

	recordReconcileStart(metricControllerHTTPTrigger)
	if got := testutil.ToFloat64(reconcilesRunning.WithLabelValues(metricControllerHTTPTrigger)); got != 1 {
		t.Fatalf("expected reconcile gauge to be 1, got %v", got)
	}
	recordReconcileDone(metricControllerHTTPTrigger)
	if got := testutil.ToFloat64(reconcilesRunning.WithLabelValues(metricControllerHTTPTrigger)); got != 0 {
		t.Fatalf("expected reconcile gauge to return to 0, got %v", got)
	}

	recordWatcherGoroutineStart(metricControllerHTTPTrigger)
	recordWatcherGoroutineStart(metricControllerHTTPTrigger)
	if got := testutil.ToFloat64(watcherGoroutinesRunning.WithLabelValues(metricControllerHTTPTrigger)); got != 2 {
		t.Fatalf("expected watcher gauge to be 2, got %v", got)
	}
	recordWatcherGoroutineDone(metricControllerHTTPTrigger)
	if got := testutil.ToFloat64(watcherGoroutinesRunning.WithLabelValues(metricControllerHTTPTrigger)); got != 1 {
		t.Fatalf("expected watcher gauge to be 1 after stop, got %v", got)
	}

	recordControllerStopped(metricControllerHTTPTrigger)
	if got := testutil.ToFloat64(controllersRunning.WithLabelValues(metricControllerHTTPTrigger)); got != 0 {
		t.Fatalf("expected stopped controller gauge to be 0, got %v", got)
	}
	if got := testutil.ToFloat64(watcherGoroutinesRunning.WithLabelValues(metricControllerHTTPTrigger)); got != 0 {
		t.Fatalf("expected stopped watcher gauge to be 0, got %v", got)
	}
}

func TestPiTriggerRunningJobsMetricTracksCounterLifecycle(t *testing.T) {
	resetRuntimeMetricsForTesting()
	sharedPiTriggerJobCounterRegistry.clear()
	defer sharedPiTriggerJobCounterRegistry.clear()

	scheme := runtime.NewScheme()
	if err := batchv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add batch scheme: %v", err)
	}
	fakeClient := ctrlclientfake.NewClientBuilder().WithScheme(scheme).Build()

	counter := sharedPiTriggerJobCounterRegistry.get("default/pi")
	trigger := &triggersv1.PiTrigger{ObjectMeta: metav1.ObjectMeta{Name: "pi", Namespace: "default"}}

	reserved, running, err := counter.reserveSlot(context.Background(), fakeClient, trigger, 0)
	if err != nil {
		t.Fatalf("reserve slot: %v", err)
	}
	if !reserved || running != 1 {
		t.Fatalf("expected unlimited reserve to succeed with running=1, got reserved=%v running=%d", reserved, running)
	}
	if got := testutil.ToFloat64(piTriggerRunningJobs.WithLabelValues("default/pi")); got != 1 {
		t.Fatalf("expected running jobs gauge to be 1, got %v", got)
	}

	counter.releaseReservedSlot()
	if got := testutil.ToFloat64(piTriggerRunningJobs.WithLabelValues("default/pi")); got != 0 {
		t.Fatalf("expected running jobs gauge to return to 0 after release, got %v", got)
	}

	counter.running = 1
	counter.releaseTerminalJob(&batchv1.Job{ObjectMeta: metav1.ObjectMeta{UID: ktypes.UID("job-1")}})
	if got := testutil.ToFloat64(piTriggerRunningJobs.WithLabelValues("default/pi")); got != 0 {
		t.Fatalf("expected terminal job release to update gauge to 0, got %v", got)
	}

	sharedPiTriggerJobCounterRegistry.remove("default/pi")
	if _, err := piTriggerRunningJobs.GetMetricWithLabelValues("default/pi"); err == nil {
		// Accessing a child recreates it, so verify removal by observing the reset value.
		if got := testutil.ToFloat64(piTriggerRunningJobs.WithLabelValues("default/pi")); got != 0 {
			t.Fatalf("expected deleted running jobs gauge to read as 0 when recreated, got %v", got)
		}
	}
}

func resetRuntimeMetricsForTesting() {
	controllersRunning.Reset()
	reconcilesRunning.Reset()
	watcherGoroutinesRunning.Reset()
	piTriggerRunningJobs.Reset()
}
