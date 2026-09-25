package watcher

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

func TestGlobalDeletionWatcherStartCancelsRegisteredTaskOnDelete(t *testing.T) {
	fakeWatch := watch.NewRaceFreeFake()
	informer := newHTTPTriggerInformer(fakeWatch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		t.Fatal("failed to sync informer cache")
	}

	watcher := NewGlobalDeletionWatcher()
	if err := watcher.Start(ctx, informer); err != nil {
		t.Fatalf("start watcher: %v", err)
	}

	deleted := make(chan struct{}, 1)
	watcher.RegisterTask("default/example", func() {
		select {
		case deleted <- struct{}{}:
		default:
		}
	})

	fakeWatch.Delete(&triggersv1.HTTPTrigger{ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"}})

	select {
	case <-deleted:
	case <-time.After(2 * time.Second):
		t.Fatal("expected registered task to be cancelled after delete event")
	}
}

func TestGlobalDeletionWatcherUnregisterSkipsCancellation(t *testing.T) {
	watcher := NewGlobalDeletionWatcher()

	var cancelled atomic.Bool
	watcher.RegisterTask("default/example", func() {
		cancelled.Store(true)
	})
	watcher.UnregisterTask("default/example")
	watcher.handleDelete("default", "example")

	if cancelled.Load() {
		t.Fatal("expected unregistered task not to be cancelled")
	}
}

func TestGlobalDeletionWatcherHandlesDeletedFinalStateUnknown(t *testing.T) {
	watcher := NewGlobalDeletionWatcher()

	var cancelled atomic.Bool
	watcher.RegisterTask("default/example", func() {
		cancelled.Store(true)
	})

	watcher.processDeletedObject(cache.DeletedFinalStateUnknown{Obj: &triggersv1.PiTrigger{
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "default"},
	}})

	if !cancelled.Load() {
		t.Fatal("expected tombstone delete event to cancel registered task")
	}
}

func TestGlobalDeletionWatcherIgnoresUnknownDeletePayload(t *testing.T) {
	watcher := NewGlobalDeletionWatcher()
	watcher.processDeletedObject(cache.DeletedFinalStateUnknown{Obj: struct{}{}})
}

func newHTTPTriggerInformer(fakeWatch *watch.RaceFreeFakeWatcher) cache.SharedIndexInformer {
	listWatch := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return &triggersv1.HTTPTriggerList{}, nil
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return fakeWatch, nil
		},
	}

	return cache.NewSharedIndexInformer(listWatch, &triggersv1.HTTPTrigger{}, 0, cache.Indexers{})
}
