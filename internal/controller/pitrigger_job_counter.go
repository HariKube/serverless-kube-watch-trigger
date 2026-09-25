package controller

import (
	"context"
	"sync"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/labels"
	ktypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
)

const (
	piTriggerJobCountRefreshInterval = time.Minute
	piTriggerJobSlotRetryDelay       = 2 * time.Second
)

var sharedPiTriggerJobCounterRegistry = &piTriggerJobCounterRegistry{}

type piTriggerJobCounterRegistry struct {
	mu       sync.Mutex
	counters map[string]*piTriggerJobCounter
}

type piTriggerJobCounter struct {
	mu                sync.Mutex
	running           int
	lastSync          time.Time
	completedTerminal map[ktypes.UID]struct{}
}

func (r *piTriggerJobCounterRegistry) init() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.counters == nil {
		r.counters = map[string]*piTriggerJobCounter{}
	}
}

func (r *piTriggerJobCounterRegistry) get(key string) *piTriggerJobCounter {
	r.init()

	r.mu.Lock()
	defer r.mu.Unlock()

	if counter, ok := r.counters[key]; ok {
		return counter
	}

	counter := &piTriggerJobCounter{completedTerminal: map[ktypes.UID]struct{}{}}
	r.counters[key] = counter

	return counter
}

func (r *piTriggerJobCounterRegistry) remove(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.counters, key)
}

func (r *piTriggerJobCounterRegistry) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.counters = map[string]*piTriggerJobCounter{}
}

func (c *piTriggerJobCounter) reserveSlot(ctx context.Context, lister client.Client, trigger *triggersv1.PiTrigger, maxJobs int) (bool, int, error) {
	if maxJobs <= 0 {
		return true, 0, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.completedTerminal == nil {
		c.completedTerminal = map[ktypes.UID]struct{}{}
	}

	if c.lastSync.IsZero() || time.Since(c.lastSync) >= piTriggerJobCountRefreshInterval {
		running, currentJobs, err := countActivePiTriggerJobs(ctx, lister, trigger.Namespace, trigger.Name)
		if err != nil {
			return false, c.running, err
		}

		c.running = running
		c.lastSync = time.Now()
		for uid := range c.completedTerminal {
			if _, ok := currentJobs[uid]; !ok {
				delete(c.completedTerminal, uid)
			}
		}
	}

	if c.running >= maxJobs {
		return false, c.running, nil
	}

	c.running++

	return true, c.running, nil
}

func (c *piTriggerJobCounter) releaseTerminalJob(job *batchv1.Job) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.completedTerminal == nil {
		c.completedTerminal = map[ktypes.UID]struct{}{}
	}
	if _, ok := c.completedTerminal[job.UID]; ok {
		return c.running
	}

	c.completedTerminal[job.UID] = struct{}{}
	if c.running > 0 {
		c.running--
	}

	return c.running
}

func (c *piTriggerJobCounter) releaseReservedSlot() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running > 0 {
		c.running--
	}

	return c.running
}

func countActivePiTriggerJobs(ctx context.Context, lister client.Client, namespace, triggerName string) (int, map[ktypes.UID]struct{}, error) {
	jobList := &batchv1.JobList{}
	if err := lister.List(ctx, jobList, &client.ListOptions{
		Namespace:     namespace,
		LabelSelector: piTriggerJobLabelSelector(triggerName),
	}); err != nil {
		return 0, nil, err
	}

	currentJobs := make(map[ktypes.UID]struct{}, len(jobList.Items))
	running := 0
	for i := range jobList.Items {
		job := &jobList.Items[i]
		currentJobs[job.UID] = struct{}{}
		_, terminal, _ := derivePiJobResult(job)
		if !terminal {
			running++
		}
	}

	return running, currentJobs, nil
}

func piTriggerJobLabelSelector(triggerName string) labels.Selector {
	return labels.SelectorFromSet(labels.Set{
		piTriggerManagedLabel:     "true",
		piTriggerTriggerNameLabel: triggerName,
	})
}
