package partition

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

type ConfigMapWatcher struct {
	clientset      kubernetes.Interface
	namespace      string
	configMapName  string
	podName        string
	onReset        func(isEmpty bool)
	deadmanTimeout time.Duration
	retryDelay     time.Duration
	signalChan     chan os.Signal
}

func NewConfigMapWatcher(
	clientset kubernetes.Interface,
	namespace, configMapName, podName string,
	onReset func(isEmpty bool),
) *ConfigMapWatcher {
	return &ConfigMapWatcher{
		clientset:      clientset,
		namespace:      namespace,
		configMapName:  configMapName,
		podName:        podName,
		onReset:        onReset,
		deadmanTimeout: defaultDeadmanTimeout,
		retryDelay:     2 * time.Second,
	}
}

func (cmw *ConfigMapWatcher) Start(ctx context.Context) {
	if cmw == nil || cmw.clientset == nil {
		<-ctx.Done()
		return
	}

	deadmanTimer := time.NewTimer(cmw.deadmanTimeout)
	defer deadmanTimer.Stop()

	sigCh := cmw.signalChan
	if sigCh == nil {
		sigCh = make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(sigCh)
	}

	go func() {
		select {
		case <-sigCh:
			cmw.WipeConfigMap(context.Background())
		case <-ctx.Done():
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-deadmanTimer.C:
			panic("configmap watcher received no API events before the deadman timeout elapsed")
		default:
		}

		watcher, err := cmw.clientset.CoreV1().ConfigMaps(cmw.namespace).Watch(
			ctx,
			metav1.SingleObject(metav1.ObjectMeta{Name: cmw.configMapName}),
		)
		if err != nil {
			if !sleepContext(ctx, cmw.retryDelay) {
				return
			}
			continue
		}

		for event := range watcher.ResultChan() {
			if event.Type != watch.Added && event.Type != watch.Modified {
				continue
			}
			resetTimer(deadmanTimer, cmw.deadmanTimeout)

			cm, ok := event.Object.(*corev1.ConfigMap)
			if !ok || cmw.onReset == nil {
				continue
			}
			cmw.onReset(len(cm.Data) == 0)
		}
	}
}

func (cmw *ConfigMapWatcher) WipeConfigMap(ctx context.Context) {
	if cmw == nil || cmw.clientset == nil {
		return
	}

	cm, err := cmw.clientset.CoreV1().ConfigMaps(cmw.namespace).Get(ctx, cmw.configMapName, metav1.GetOptions{})
	if err != nil {
		return
	}
	if cm.Data == nil {
		return
	}

	updated := cm.DeepCopy()
	for key, owner := range updated.Data {
		switch {
		case key == heartbeatKey(cmw.podName):
			delete(updated.Data, key)
		case strings.HasPrefix(key, partitionKeyPrefix) && owner == cmw.podName:
			delete(updated.Data, key)
		}
	}
	if equalStringMap(cm.Data, updated.Data) {
		return
	}
	_, _ = cmw.clientset.CoreV1().ConfigMaps(cmw.namespace).Update(ctx, updated, metav1.UpdateOptions{})
}

func resetTimer(timer *time.Timer, next time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(next)
}
