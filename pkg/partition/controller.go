package partition

import (
	"context"
	"fmt"
	"hash/fnv"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	DistributionLabelKey        = "triggers.harikube.info/distribution"
	DefaultConfigMapName        = "distribution-partition-map"
	TotalPartitions             = 100
	defaultClaimRefreshInterval = 4 * time.Minute
	defaultDeadmanTimeout       = 5 * time.Minute
	deadmanGracePeriod          = time.Minute
	maxClaimRefreshConflicts    = 8
	heartbeatKeyPrefix          = "heartbeat/"
	partitionKeyPrefix          = "partition/"
)

type Mode string

const (
	ModeSingleWorker         Mode = "single-worker"
	ModeDistributedPartition Mode = "distributed-partition"
)

type Options struct {
	ClaimRefreshInterval time.Duration
	DeadmanTimeout       time.Duration
}

type Controller struct {
	clientset            kubernetes.Interface
	namespace            string
	configMapName        string
	podName              string
	mode                 Mode
	claimRefreshInterval time.Duration
	deadmanTimeout       time.Duration

	mu              sync.RWMutex
	ownedPartitions map[string]struct{}
	listeners       []func(context.Context)
}

func NewSingleWorkerController() *Controller {
	owned := make(map[string]struct{}, TotalPartitions)
	for _, partition := range allPartitions() {
		owned[partition] = struct{}{}
	}

	return &Controller{
		mode:                 ModeSingleWorker,
		claimRefreshInterval: defaultClaimRefreshInterval,
		deadmanTimeout:       defaultDeadmanTimeout,
		ownedPartitions:      owned,
	}
}

func NewDistributedController(clientset kubernetes.Interface, namespace, podName string) *Controller {
	return NewDistributedControllerWithOptions(clientset, namespace, podName, Options{})
}

func NewDistributedControllerWithOptions(
	clientset kubernetes.Interface,
	namespace, podName string,
	opts Options,
) *Controller {
	if namespace == "" {
		namespace = os.Getenv("POD_NAMESPACE")
	}
	if namespace == "" {
		namespace = "default"
	}
	if podName == "" {
		podName = os.Getenv("POD_NAME")
	}
	if podName == "" {
		podName = os.Getenv("HOSTNAME")
	}
	if podName == "" {
		podName = "serverless-kube-watch-trigger"
	}

	claimRefreshInterval, deadmanTimeout := normalizeIntervals(opts)

	return &Controller{
		clientset:            clientset,
		namespace:            namespace,
		configMapName:        DefaultConfigMapName,
		podName:              podName,
		mode:                 ModeDistributedPartition,
		claimRefreshInterval: claimRefreshInterval,
		deadmanTimeout:       deadmanTimeout,
		ownedPartitions:      map[string]struct{}{},
	}
}

func normalizeIntervals(opts Options) (time.Duration, time.Duration) {
	claimRefreshInterval := opts.ClaimRefreshInterval
	if claimRefreshInterval <= 0 {
		claimRefreshInterval = defaultClaimRefreshInterval
	}

	deadmanTimeout := opts.DeadmanTimeout
	if deadmanTimeout <= 0 {
		deadmanTimeout = defaultDeadmanTimeout
	}
	if deadmanTimeout <= claimRefreshInterval {
		deadmanTimeout = claimRefreshInterval + deadmanGracePeriod
	}

	return claimRefreshInterval, deadmanTimeout
}

func (c *Controller) Mode() Mode {
	if c == nil {
		return ModeSingleWorker
	}
	return c.mode
}

func (c *Controller) AddChangeListener(listener func(context.Context)) {
	if c == nil || listener == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.listeners = append(c.listeners, listener)
}

func (c *Controller) Start(ctx context.Context) error {
	if c == nil || c.mode == ModeSingleWorker {
		<-ctx.Done()
		return nil
	}

	for {
		if err := c.Refresh(ctx); err == nil {
			break
		}
		if !sleepContext(ctx, 2*time.Second) {
			return nil
		}
	}
	c.notifyListeners(ctx)

	watcher := NewConfigMapWatcher(c.clientset, c.namespace, c.configMapName, c.podName, func(bool) {
		refreshCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := c.Refresh(refreshCtx); err == nil {
			c.notifyListeners(refreshCtx)
		}
	})
	watcher.deadmanTimeout = c.deadmanTimeout
	watcher.retryDelay = 2 * time.Second
	go watcher.Start(ctx)

	stagger := staggerDuration(c.podName)
	if stagger > 0 {
		if !sleepContext(ctx, stagger) {
			return nil
		}
	}

	ticker := time.NewTicker(c.claimRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			before := c.OwnedPartitions()
			if err := c.Refresh(ctx); err != nil {
				continue
			}
			after := c.OwnedPartitions()
			if !samePartitions(before, after) {
				c.notifyListeners(ctx)
			}
		}
	}
}

func (c *Controller) NeedLeaderElection() bool {
	return false
}

func (c *Controller) OwnsObject(obj metav1.Object) bool {
	if c == nil || c.mode == ModeSingleWorker {
		return true
	}
	if obj == nil {
		return false
	}
	return c.OwnsDistribution(obj.GetLabels()[DistributionLabelKey])
}

func (c *Controller) OwnsDistribution(distribution string) bool {
	if c == nil || c.mode == ModeSingleWorker {
		return true
	}
	if distribution == "" {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.ownedPartitions[distribution]
	return ok
}

func (c *Controller) OwnedPartitions() []string {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	partitions := make([]string, 0, len(c.ownedPartitions))
	for partition := range c.ownedPartitions {
		partitions = append(partitions, partition)
	}
	sort.Strings(partitions)
	return partitions
}

func (c *Controller) Refresh(ctx context.Context) error {
	if c == nil || c.mode == ModeSingleWorker {
		return nil
	}

	for attempt := 0; attempt < maxClaimRefreshConflicts; attempt++ {
		cm, err := c.ensureConfigMap(ctx)
		if err != nil {
			return err
		}

		updated := cm.DeepCopy()
		if updated.Data == nil {
			updated.Data = map[string]string{}
		}

		now := time.Now().UTC()
		updated.Data[heartbeatKey(c.podName)] = now.Format(time.RFC3339)
		activePods := pruneStaleEntries(updated.Data, now, c.deadmanTimeout)
		activePods[c.podName] = struct{}{}

		quota := calculateQuota(len(activePods))
		owned := claimPartitions(updated.Data, c.podName, quota)
		c.setOwnedPartitions(owned)

		if equalStringMap(cm.Data, updated.Data) {
			return nil
		}

		if _, err := c.clientset.CoreV1().ConfigMaps(c.namespace).Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return err
		}

		return nil
	}

	return fmt.Errorf("failed to refresh partition claims after %d retries", maxClaimRefreshConflicts)
}

func (c *Controller) ensureConfigMap(ctx context.Context) (*corev1.ConfigMap, error) {
	cm, err := c.clientset.CoreV1().ConfigMaps(c.namespace).Get(ctx, c.configMapName, metav1.GetOptions{})
	if err == nil {
		return cm, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}

	created, createErr := c.clientset.CoreV1().ConfigMaps(c.namespace).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.configMapName,
			Namespace: c.namespace,
		},
		Data: map[string]string{},
	}, metav1.CreateOptions{})
	if createErr == nil {
		return created, nil
	}
	if apierrors.IsAlreadyExists(createErr) {
		return c.clientset.CoreV1().ConfigMaps(c.namespace).Get(ctx, c.configMapName, metav1.GetOptions{})
	}
	return nil, createErr
}

func (c *Controller) notifyListeners(ctx context.Context) {
	c.mu.RLock()
	listeners := append([]func(context.Context){}, c.listeners...)
	c.mu.RUnlock()
	for _, listener := range listeners {
		listener(ctx)
	}
}

func (c *Controller) setOwnedPartitions(partitions []string) {
	owned := make(map[string]struct{}, len(partitions))
	for _, partition := range partitions {
		owned[partition] = struct{}{}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.ownedPartitions = owned
}

func calculateQuota(activeReplicas int) int {
	if activeReplicas <= 1 {
		return TotalPartitions
	}
	return int(math.Ceil(float64(TotalPartitions) / float64(activeReplicas)))
}

func claimPartitions(data map[string]string, podName string, quota int) []string {
	owned := make([]string, 0, quota)
	for _, partition := range allPartitions() {
		if data[partitionKey(partition)] == podName {
			owned = append(owned, partition)
		}
	}

	for len(owned) > quota {
		partition := owned[len(owned)-1]
		delete(data, partitionKey(partition))
		owned = owned[:len(owned)-1]
	}
	if len(owned) >= quota {
		return owned
	}

	for _, partition := range allPartitions() {
		key := partitionKey(partition)
		owner := strings.TrimSpace(data[key])
		if owner != "" && owner != podName {
			continue
		}
		if owner == podName {
			continue
		}
		data[key] = podName
		owned = append(owned, partition)
		if len(owned) == quota {
			break
		}
	}

	return owned
}

func pruneStaleEntries(data map[string]string, now time.Time, staleAfter time.Duration) map[string]struct{} {
	activePods := map[string]struct{}{}
	stalePods := map[string]struct{}{}

	for key, raw := range data {
		if !strings.HasPrefix(key, heartbeatKeyPrefix) {
			continue
		}
		podName := strings.TrimPrefix(key, heartbeatKeyPrefix)
		timestamp, err := time.Parse(time.RFC3339, raw)
		if err != nil || now.Sub(timestamp) > staleAfter {
			delete(data, key)
			stalePods[podName] = struct{}{}
			continue
		}
		activePods[podName] = struct{}{}
	}

	for key, owner := range data {
		if !strings.HasPrefix(key, partitionKeyPrefix) {
			continue
		}
		if _, stale := stalePods[owner]; stale {
			delete(data, key)
		}
	}

	return activePods
}

func allPartitions() []string {
	partitions := make([]string, 0, TotalPartitions)
	for i := 1; i <= TotalPartitions; i++ {
		partitions = append(partitions, partitionName(i))
	}
	return partitions
}

func partitionName(index int) string {
	return "item-" + strconv.Itoa(index)
}

func heartbeatKey(podName string) string {
	return heartbeatKeyPrefix + podName
}

func partitionKey(partition string) string {
	return partitionKeyPrefix + partition
}

func staggerDuration(podName string) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte(podName))
	return time.Duration(h.Sum32()%30000) * time.Millisecond
}

func samePartitions(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func equalStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftValue := range left {
		if right[key] != leftValue {
			return false
		}
	}
	return true
}

func sleepContext(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
