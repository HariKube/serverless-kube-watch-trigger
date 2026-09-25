package partition

import (
	"context"
	"sort"
	"sync"
)

type TaskWorkerFunc func(ctx context.Context, distribution string)
type LabelPatcherFunc func(ctx context.Context, distribution string) error

type SubController struct {
	distribution string
	cancel       context.CancelFunc
	done         chan struct{}
}

type SubControllerManager struct {
	worker TaskWorkerFunc

	mu          sync.Mutex
	controllers map[string]*SubController
}

func NewSubControllerManager(worker TaskWorkerFunc) *SubControllerManager {
	return &SubControllerManager{
		worker:      worker,
		controllers: map[string]*SubController{},
	}
}

func (m *SubControllerManager) EnsureStarted(ctx context.Context, distribution string) {
	if m == nil || m.worker == nil || distribution == "" {
		return
	}

	m.mu.Lock()
	if _, exists := m.controllers[distribution]; exists {
		m.mu.Unlock()
		return
	}

	runCtx, cancel := context.WithCancel(ctx)
	sub := &SubController{distribution: distribution, cancel: cancel, done: make(chan struct{})}
	m.controllers[distribution] = sub
	m.mu.Unlock()

	go func() {
		defer close(sub.done)
		m.worker(runCtx, distribution)
	}()
}

func (m *SubControllerManager) Stop(distribution string) {
	if m == nil || distribution == "" {
		return
	}

	m.mu.Lock()
	sub, exists := m.controllers[distribution]
	if exists {
		delete(m.controllers, distribution)
	}
	m.mu.Unlock()
	if !exists {
		return
	}

	sub.cancel()
	<-sub.done
}

func (m *SubControllerManager) Sync(ctx context.Context, activeDistributions []string) {
	if m == nil {
		return
	}

	desired := make(map[string]struct{}, len(activeDistributions))
	for _, distribution := range activeDistributions {
		desired[distribution] = struct{}{}
		m.EnsureStarted(ctx, distribution)
	}

	for _, distribution := range m.Active() {
		if _, keep := desired[distribution]; keep {
			continue
		}
		m.Stop(distribution)
	}
}

func (m *SubControllerManager) Complete(ctx context.Context, distribution string, patcher LabelPatcherFunc) error {
	if m == nil {
		return nil
	}
	defer m.Stop(distribution)
	if patcher == nil {
		return nil
	}
	return patcher(ctx, distribution)
}

func (m *SubControllerManager) Active() []string {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	active := make([]string, 0, len(m.controllers))
	for distribution := range m.controllers {
		active = append(active, distribution)
	}
	sort.Strings(active)
	return active
}
