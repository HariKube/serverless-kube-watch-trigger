package partition

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestSubControllerManagerSyncStartsAndStopsControllers(t *testing.T) {
	started := make(chan string, 2)
	stopped := make(chan string, 2)

	manager := NewSubControllerManager(func(ctx context.Context, distribution string) {
		started <- distribution
		<-ctx.Done()
		stopped <- distribution
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	manager.Sync(ctx, []string{"item-1", "item-2"})
	assertEventuallySet(t, started, "item-1", "item-2")

	manager.Sync(ctx, []string{"item-2"})
	assertEventuallyContains(t, stopped, "item-1")

	active := manager.Active()
	if len(active) != 1 || active[0] != "item-2" {
		t.Fatalf("expected only item-2 to remain active, got %#v", active)
	}
}

func TestSubControllerManagerCompleteInvokesPatcherAndStopsController(t *testing.T) {
	var patched atomic.Bool
	manager := NewSubControllerManager(func(ctx context.Context, distribution string) {
		<-ctx.Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.EnsureStarted(ctx, "item-9")

	err := manager.Complete(context.Background(), "item-9", func(ctx context.Context, distribution string) error {
		if distribution != "item-9" {
			t.Fatalf("expected distribution item-9, got %s", distribution)
		}
		patched.Store(true)
		return nil
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !patched.Load() {
		t.Fatal("expected patcher to be invoked")
	}
	if len(manager.Active()) != 0 {
		t.Fatal("expected completed controller to be removed")
	}
}

func assertEventuallyContains(t *testing.T, ch <-chan string, want string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-ch:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", want)
		}
	}
}

func assertEventuallySet(t *testing.T, ch <-chan string, wants ...string) {
	t.Helper()
	remaining := make(map[string]struct{}, len(wants))
	for _, want := range wants {
		remaining[want] = struct{}{}
	}
	deadline := time.After(2 * time.Second)
	for len(remaining) > 0 {
		select {
		case got := <-ch:
			delete(remaining, got)
		case <-deadline:
			t.Fatalf("timed out waiting for %#v", wants)
		}
	}
}
