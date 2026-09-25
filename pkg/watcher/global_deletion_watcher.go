package watcher

import (
	"context"
	"fmt"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// GlobalDeletionWatcher tracks active trigger workers and cancels them when the
// underlying HTTPTrigger or PiTrigger resource is physically deleted.
//
// The caller owns informer lifecycle management. Start only attaches the delete
// handler so the same watcher can be reused with controller-managed informers
// without risking duplicate Run calls.
type deleteEventSource interface {
	AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error)
}

type GlobalDeletionWatcher struct {
	activeTasks sync.Map
}

func NewGlobalDeletionWatcher() *GlobalDeletionWatcher {
	return &GlobalDeletionWatcher{}
}

func (g *GlobalDeletionWatcher) RegisterTask(resourceKey string, cancel context.CancelFunc) {
	if resourceKey == "" || cancel == nil {
		return
	}
	g.activeTasks.Store(resourceKey, cancel)
}

func (g *GlobalDeletionWatcher) UnregisterTask(resourceKey string) {
	if resourceKey == "" {
		return
	}
	g.activeTasks.Delete(resourceKey)
}

func (g *GlobalDeletionWatcher) Start(ctx context.Context, informer deleteEventSource) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if informer == nil {
		return fmt.Errorf("global deletion watcher requires a non-nil informer")
	}

	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: g.processDeletedObject,
	})
	return err
}

func (g *GlobalDeletionWatcher) processDeletedObject(obj interface{}) {
	metaObj := deletedObjectMeta(obj)
	if metaObj == nil {
		return
	}
	g.handleDelete(metaObj.GetNamespace(), metaObj.GetName())
}

func deletedObjectMeta(obj interface{}) metav1.Object {
	switch typed := obj.(type) {
	case metav1.Object:
		return typed
	case cache.DeletedFinalStateUnknown:
		if metaObj, ok := typed.Obj.(metav1.Object); ok {
			return metaObj
		}
	}
	return nil
}

func (g *GlobalDeletionWatcher) handleDelete(namespace, name string) {
	if namespace == "" || name == "" {
		return
	}

	key := fmt.Sprintf("%s/%s", namespace, name)
	cancelVal, loaded := g.activeTasks.LoadAndDelete(key)
	if !loaded {
		return
	}

	cancel, ok := cancelVal.(context.CancelFunc)
	if !ok || cancel == nil {
		return
	}
	cancel()
}
