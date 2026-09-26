package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
	"github.com/harikube/serverless-kube-watch-trigger/pkg/lease"
	"github.com/harikube/serverless-kube-watch-trigger/pkg/partition"
)

func newPiReconciler() *PiTriggerReconciler {
	r := &PiTriggerReconciler{
		Client:              k8sClient,
		DynamicClient:       dynamicClient,
		Scheme:              k8sClient.Scheme(),
		Recorder:            record.NewFakeRecorder(10),
		PartitionController: partition.NewSingleWorkerController(),
		ctx:                 ctx,
		runningTriggersLock: sync.Mutex{},
		runningTriggers:     map[string]func(){},
		triggerLocksLock:    sync.Mutex{},
		triggerLocks:        map[string]*sync.Mutex{},
	}
	DeferCleanup(func() {
		r.runningTriggersLock.Lock()
		for _, c := range r.runningTriggers {
			c()
		}
		r.runningTriggers = map[string]func(){}
		r.runningTriggersLock.Unlock()
		sharedPiTriggerJobCounterRegistry.clear()
	})
	return r
}

func cleanupPiTrigger(ctx context.Context, name string) {
	trigger := &triggersv1.PiTrigger{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, trigger); err == nil {
		_ = k8sClient.Delete(ctx, trigger)
	}
}

func cleanupConfigMap(ctx context.Context, name string) {
	configMap := &corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, configMap); err == nil {
		_ = k8sClient.Delete(ctx, configMap)
	}
}

func cleanupJob(ctx context.Context, name string) {
	job := &batchv1.Job{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, job); err == nil {
		_ = k8sClient.Delete(ctx, job)
	}
}

func createPiAgentConfigSecret(ctx context.Context, name string) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Data: map[string][]byte{
			"settings.json":     []byte(`{"provider":"test"}`),
			"models.json":       []byte(`[]`),
			"models-store.json": []byte(`{}`),
			"auth.json":         []byte(`{}`),
		},
	}
	Expect(k8sClient.Create(ctx, secret)).To(Succeed())
}

func createPiAgentConfigMaps(ctx context.Context, promptsName, skillsName string) {
	prompts := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: promptsName, Namespace: "default"},
		Data:       map[string]string{"example.md": "# prompt"},
	}
	skills := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: skillsName, Namespace: "default"},
		Data:       map[string]string{"SKILL.md": "# skill"},
	}
	Expect(k8sClient.Create(ctx, prompts)).To(Succeed())
	Expect(k8sClient.Create(ctx, skills)).To(Succeed())
}

var _ = Describe("PiTrigger Controller", func() {
	const ns = "default"
	bgCtx := context.Background()

	Context("Reconcile - trigger not found", func() {
		It("returns no error when the resource does not exist", func() {
			r := newPiReconciler()
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "does-not-exist-pi", Namespace: ns}})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("Reconcile - invalid trigger content", func() {
		const name = "pitrigger-invalid"

		AfterEach(func() {
			cleanupPiTrigger(bgCtx, name)
		})

		It("records ErrorReason in status for a missing agent config secret", func() {
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
					},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: "missing-pi-agent-config"},
						PromptsConfigMapRef: corev1.LocalObjectReference{Name: "missing-prompts"},
						SkillsConfigMapRef:  corev1.LocalObjectReference{Name: "missing-skills"},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newPiReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			updated := &triggersv1.PiTrigger{}
			Eventually(func() string {
				_ = k8sClient.Get(bgCtx, nsn, updated)
				return updated.Status.ErrorReason
			}, 5*time.Second, 200*time.Millisecond).ShouldNot(BeEmpty())
		})
	})

	Context("Annotation lease", func() {
		const (
			name          = "pitrigger-annotation-lease"
			secretName    = "pitrigger-annotation-secret"
			promptsCMName = "pitrigger-annotation-prompts"
			skillsCMName  = "pitrigger-annotation-skills"
		)

		AfterEach(func() {
			cleanupPiTrigger(bgCtx, name)
			cleanupConfigMap(bgCtx, promptsCMName)
			cleanupConfigMap(bgCtx, skillsCMName)
			cleanupSecret(bgCtx, secretName)
		})

		It("requeues while an active annotation lease is present using the trigger-specific lock duration", func() {
			const triggerLockDuration = 5 * time.Second
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: ns,
					Annotations: map[string]string{
						lease.AnnotationKey: time.Now().UTC().Format(time.RFC3339),
					},
				},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:     metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:   []string{ns},
						LockDuration: metav1.Duration{Duration: triggerLockDuration},
					},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef: corev1.LocalObjectReference{Name: promptsCMName},
						SkillsConfigMapRef:  corev1.LocalObjectReference{Name: skillsCMName},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newPiReconciler()

			result, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: ns}})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))
			Expect(result.RequeueAfter).To(BeNumerically("<=", triggerLockDuration))

			r.runningTriggersLock.Lock()
			_, running := r.runningTriggers[ns+"/"+name]
			r.runningTriggersLock.Unlock()
			Expect(running).To(BeFalse())
		})

		It("clears the annotation lease after a successful reconcile", func() {
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)

			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:     metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:   []string{ns},
						LockDuration: metav1.Duration{Duration: 30 * time.Second},
					},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef: corev1.LocalObjectReference{Name: promptsCMName},
						SkillsConfigMapRef:  corev1.LocalObjectReference{Name: skillsCMName},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newPiReconciler()

			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: ns}})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				updated := &triggersv1.PiTrigger{}
				g.Expect(k8sClient.Get(bgCtx, types.NamespacedName{Name: name, Namespace: ns}, updated)).To(Succeed())
				g.Expect(updated.Status.Phase).To(Equal(triggersv1.TriggerPhaseRunning))
				g.Expect(updated.Annotations).NotTo(HaveKey(lease.AnnotationKey))
			}, 5*time.Second, 100*time.Millisecond).Should(Succeed())
		})

		It("clears a stale annotation lease even when the trigger is already running", func() {
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)

			staleLockedAt := time.Now().UTC().Add(-time.Minute)
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: ns,
					Annotations: map[string]string{
						lease.AnnotationKey: staleLockedAt.Format(time.RFC3339),
					},
				},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:     metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:   []string{ns},
						LockDuration: metav1.Duration{Duration: 5 * time.Second},
					},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef: corev1.LocalObjectReference{Name: promptsCMName},
						SkillsConfigMapRef:  corev1.LocalObjectReference{Name: skillsCMName},
					},
				},
				Status: triggersv1.PiTriggerStatus{Phase: triggersv1.TriggerPhaseRunning, LastGeneration: 1},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
			Expect(k8sClient.Status().Update(bgCtx, trigger)).To(Succeed())

			r := newPiReconciler()

			result, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: ns}})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))

			Eventually(func(g Gomega) {
				updated := &triggersv1.PiTrigger{}
				g.Expect(k8sClient.Get(bgCtx, types.NamespacedName{Name: name, Namespace: ns}, updated)).To(Succeed())
				g.Expect(updated.Status.Phase).To(Equal(triggersv1.TriggerPhaseRunning))
				g.Expect(updated.Status.LastGeneration).To(Equal(updated.Generation))
				g.Expect(updated.Annotations).NotTo(HaveKey(lease.AnnotationKey))
			}, 5*time.Second, 100*time.Millisecond).Should(Succeed())
		})
	})

	Context("watcher error handling", func() {
		It("records a detailed warning event after patching trigger status", func() {
			recorder := record.NewFakeRecorder(1)
			runningTriggersLock := sync.Mutex{}
			runningTriggers := map[string]func(){"default/pitrigger-event": func() {}}
			trigger := &triggersv1.PiTrigger{ObjectMeta: metav1.ObjectMeta{Name: "pitrigger-event", Namespace: ns}}

			cancelCalled := false
			stopCalled := false
			runningTriggers["default/pitrigger-event"] = func() { cancelCalled = true }

			var (
				patchesMu                   sync.Mutex
				patchedErrorTime            metav1.Time
				patchedErrorReason          string
				patchedErrorResourceVersion string
			)

			handleTriggerWatcherError(
				context.Background(),
				errors.New("closed channel"),
				logr.Discard(),
				recorder,
				trigger,
				"default/pitrigger-event",
				"42",
				&runningTriggersLock,
				runningTriggers,
				context.Background().Done(),
				func() { stopCalled = true },
				func(_ context.Context, errorTime metav1.Time, errorReason, errorResourceVersion string) (bool, error) {
					patchesMu.Lock()
					defer patchesMu.Unlock()
					patchedErrorTime = errorTime
					patchedErrorReason = errorReason
					patchedErrorResourceVersion = errorResourceVersion
					return true, nil
				},
			)

			Eventually(func() string {
				patchesMu.Lock()
				defer patchesMu.Unlock()
				return patchedErrorReason
			}, 5*time.Second, 100*time.Millisecond).Should(Equal("closed channel"))
			patchesMu.Lock()
			defer patchesMu.Unlock()
			Expect(patchedErrorTime.IsZero()).To(BeFalse())
			Expect(patchedErrorResourceVersion).To(Equal("42"))
			Expect(cancelCalled).To(BeTrue())
			Expect(stopCalled).To(BeTrue())
			Expect(runningTriggers).NotTo(HaveKey("default/pitrigger-event"))

			var event string
			Eventually(recorder.Events, 5*time.Second, 100*time.Millisecond).Should(Receive(&event))
			Expect(event).To(ContainSubstring("Warning"))
			Expect(event).To(ContainSubstring("WatcherClosed"))
			Expect(event).To(ContainSubstring("default/pitrigger-event"))
			Expect(event).To(ContainSubstring("closed channel"))
			Expect(event).To(ContainSubstring("resourceVersion=42"))
		})

		It("does not patch status when the controller context is cancelled (shutdown)", func() {
			runningTriggersLock := sync.Mutex{}
			runningTriggers := map[string]func(){}
			trigger := &triggersv1.PiTrigger{ObjectMeta: metav1.ObjectMeta{Name: "pitrigger-shutdown", Namespace: ns}}

			cancelCalled := false
			runningTriggers["default/pitrigger-shutdown"] = func() { cancelCalled = true }
			patchCalls := &atomic.Int32{}

			shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
			shutdownCancel()

			handleTriggerWatcherError(
				shutdownCtx,
				errors.New("shutting down"),
				logr.Discard(),
				record.NewFakeRecorder(1),
				trigger,
				"default/pitrigger-shutdown",
				"0",
				&runningTriggersLock,
				runningTriggers,
				context.Background().Done(),
				func() {},
				func(_ context.Context, _ metav1.Time, _, _ string) (bool, error) {
					patchCalls.Add(1)
					return true, nil
				},
			)

			Expect(cancelCalled).To(BeTrue())
			Expect(runningTriggers).NotTo(HaveKey("default/pitrigger-shutdown"))
			Consistently(func() int32 { return patchCalls.Load() }, 2*time.Second, 100*time.Millisecond).Should(BeZero())
		})
	})

	Context("Reconcile - successful Pi job dispatch", func() {
		const (
			triggerName   = "pitrigger-success"
			configMapName = "pitrigger-configmap"
			secretName    = "pitrigger-agent-config"
			promptsCMName = "pitrigger-agent-prompts"
			skillsCMName  = "pitrigger-agent-skills"
		)

		AfterEach(func() {
			cleanupConfigMap(bgCtx, configMapName)
			cleanupConfigMap(bgCtx, promptsCMName)
			cleanupConfigMap(bgCtx, skillsCMName)
			cleanupPiTrigger(bgCtx, triggerName)
			cleanupSecret(bgCtx, secretName)
		})

		It("dispatches events created after the trigger even when reconcile starts later", func() {
			const (
				lateTriggerName   = "pitrigger-success-late"
				lateConfigMapName = "pitrigger-configmap-late"
				lateSecretName    = "pitrigger-agent-config-late"
				latePromptsName   = "pitrigger-agent-prompts-late"
				lateSkillsName    = "pitrigger-agent-skills-late"
			)
			DeferCleanup(func() {
				cleanupConfigMap(bgCtx, lateConfigMapName)
				cleanupConfigMap(bgCtx, latePromptsName)
				cleanupConfigMap(bgCtx, lateSkillsName)
				cleanupPiTrigger(bgCtx, lateTriggerName)
				cleanupSecret(bgCtx, lateSecretName)
			})

			createPiAgentConfigSecret(bgCtx, lateSecretName)
			createPiAgentConfigMaps(bgCtx, latePromptsName, lateSkillsName)
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: lateTriggerName, Namespace: ns},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:      metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:    []string{ns},
						FieldSelector: []string{fmt.Sprintf("metadata.name=%s", lateConfigMapName)},
						EventType:     []triggersv1.EventType{triggersv1.EventTypeAdded},
						Concurrency:   1,
					},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: lateSecretName},
						PromptsConfigMapRef: corev1.LocalObjectReference{Name: latePromptsName},
						SkillsConfigMapRef:  corev1.LocalObjectReference{Name: lateSkillsName},
						WorkingDir:          "/workspace",
						NoExtensions:        true,
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: lateConfigMapName, Namespace: ns}, Data: map[string]string{"key": "value"}}
			Expect(k8sClient.Create(bgCtx, configMap)).To(Succeed())

			r := newPiReconciler()
			nsn := types.NamespacedName{Name: lateTriggerName, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			jobList := &batchv1.JobList{}
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.List(bgCtx, jobList, client.InNamespace(ns), client.MatchingLabels{piTriggerTriggerNameLabel: lateTriggerName})).To(Succeed())
				g.Expect(jobList.Items).To(HaveLen(1))
			}, 10*time.Second, 200*time.Millisecond).Should(Succeed())

			cleanupJob(bgCtx, jobList.Items[0].Name)
			cleanupConfigMap(bgCtx, jobList.Items[0].Annotations[piTriggerInputConfigMapAnnotation])
		})

		It("renders prompt input and creates a worker Job per event", func() {
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)
			backoffLimit := int32(4)
			ttlSeconds := int32(300)
			workerTimeout := metav1.Duration{Duration: 7 * time.Minute}
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: triggerName, Namespace: ns},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:      metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:    []string{ns},
						FieldSelector: []string{fmt.Sprintf("metadata.name=%s", configMapName)},
						EventType:     []triggersv1.EventType{triggersv1.EventTypeAdded},
						Concurrency:   1,
					},
					Agent: triggersv1.PiAgentSpec{
						Image:                   "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:         corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef:     corev1.LocalObjectReference{Name: promptsCMName},
						SkillsConfigMapRef:      corev1.LocalObjectReference{Name: skillsCMName},
						Provider:                "openai",
						Model:                   "gpt-4o-mini",
						WorkingDir:              "/workspace",
						NoExtensions:            true,
						Extensions:              []string{"npm:pi-graft", "npm:custom-tool"},
						Timeout:                 workerTimeout,
						ServiceAccountName:      "pi-trigger-runner",
						ImagePullPolicy:         corev1.PullIfNotPresent,
						Env:                     []corev1.EnvVar{{Name: "EXTRA_FLAG", Value: "true"}},
						BackoffLimit:            &backoffLimit,
						TTLSecondsAfterFinished: &ttlSeconds,
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newPiReconciler()
			nsn := types.NamespacedName{Name: triggerName, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() bool {
				r.runningTriggersLock.Lock()
				defer r.runningTriggersLock.Unlock()
				_, ok := r.runningTriggers[nsn.String()]
				return ok
			}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())

			configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: configMapName, Namespace: ns}, Data: map[string]string{"key": "value"}}
			Expect(k8sClient.Create(bgCtx, configMap)).To(Succeed())

			jobList := &batchv1.JobList{}
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.List(bgCtx, jobList, client.InNamespace(ns), client.MatchingLabels{piTriggerTriggerNameLabel: triggerName})).To(Succeed())
				g.Expect(jobList.Items).To(HaveLen(1))
			}, 10*time.Second, 200*time.Millisecond).Should(Succeed())

			job := jobList.Items[0]
			Expect(job.Labels[piTriggerManagedLabel]).To(Equal("true"))
			Expect(job.Spec.BackoffLimit).NotTo(BeNil())
			Expect(*job.Spec.BackoffLimit).To(Equal(backoffLimit))
			Expect(job.Spec.TTLSecondsAfterFinished).NotTo(BeNil())
			Expect(*job.Spec.TTLSecondsAfterFinished).To(Equal(ttlSeconds))
			Expect(job.Spec.ActiveDeadlineSeconds).NotTo(BeNil())
			Expect(*job.Spec.ActiveDeadlineSeconds).To(Equal(int64(420)))
			Expect(job.Spec.Template.Spec.ServiceAccountName).To(Equal("pi-trigger-runner"))
			Expect(job.Spec.Template.Spec.Volumes).To(HaveLen(4))
			Expect(job.Spec.Template.Spec.Volumes[1].Secret).NotTo(BeNil())
			Expect(job.Spec.Template.Spec.Volumes[1].Secret.SecretName).To(Equal(secretName))
			Expect(job.Spec.Template.Spec.Volumes[2].ConfigMap).NotTo(BeNil())
			Expect(job.Spec.Template.Spec.Volumes[2].ConfigMap.Name).To(Equal(promptsCMName))
			Expect(job.Spec.Template.Spec.Volumes[3].ConfigMap).NotTo(BeNil())
			Expect(job.Spec.Template.Spec.Volumes[3].ConfigMap.Name).To(Equal(skillsCMName))
			Expect(job.Spec.Template.Spec.Containers).To(HaveLen(1))

			container := job.Spec.Template.Spec.Containers[0]
			Expect(container.Image).To(Equal("docker.io/mhmxs/pi-agent-empty:latest"))
			Expect(container.Command).To(BeEmpty())
			expectedPrompt, err := buildPiTriggerWorkerPrompt(trigger.Spec)
			Expect(err).NotTo(HaveOccurred())
			Expect(container.Args).To(Equal(buildPiTriggerWorkerArgs(expectedPrompt, trigger.Spec.Agent)))
			expectedSpecJSON, err := json.Marshal(trigger.Spec)
			Expect(err).NotTo(HaveOccurred())
			expectedSkill := fmt.Sprintf("sub-agent defaults base64://%s", base64.StdEncoding.EncodeToString(expectedSpecJSON))
			promptArg := container.Args[len(container.Args)-1]
			promptParts := strings.SplitN(promptArg, "Prompt: ", 2)
			Expect(promptParts).To(HaveLen(2))
			Expect(promptParts[1]).To(HavePrefix(expectedSkill))
			Expect(container.WorkingDir).To(Equal("/workspace"))
			Expect(container.Env).To(ContainElement(corev1.EnvVar{Name: "HOME", Value: piTriggerWorkerHomeDir}))
			Expect(container.Env).To(ContainElement(corev1.EnvVar{Name: "EXTRA_FLAG", Value: "true"}))
			Expect(container.VolumeMounts).To(ContainElement(corev1.VolumeMount{Name: piTriggerAgentSecretVolumeName, MountPath: piTriggerAgentConfigMountPath, ReadOnly: true}))
			Expect(container.VolumeMounts).To(ContainElement(corev1.VolumeMount{Name: piTriggerPromptsVolumeName, MountPath: piTriggerAgentPromptsMountPath, ReadOnly: true}))
			Expect(container.VolumeMounts).To(ContainElement(corev1.VolumeMount{Name: piTriggerSkillsVolumeName, MountPath: piTriggerAgentSkillsMountPath, ReadOnly: true}))

			inputConfigMapName := job.Annotations[piTriggerInputConfigMapAnnotation]
			Expect(inputConfigMapName).NotTo(BeEmpty())
			inputConfigMap := &corev1.ConfigMap{}
			Expect(k8sClient.Get(bgCtx, types.NamespacedName{Name: inputConfigMapName, Namespace: ns}, inputConfigMap)).To(Succeed())
			Expect(inputConfigMap.Data).NotTo(HaveKey("worker_config.json"))
			Expect(inputConfigMap.Data["event.json"]).To(ContainSubstring(`"eventType": "ADDED"`))
			Expect(inputConfigMap.Data["metadata.json"]).To(ContainSubstring(`"triggerName": "pitrigger-success"`))

			cleanupJob(bgCtx, job.Name)
			cleanupConfigMap(bgCtx, inputConfigMapName)
		})
	})

	Context("Reconcile - maxJobs throttling", func() {
		const (
			triggerName   = "pitrigger-maxjobs"
			secretName    = "pitrigger-maxjobs-agent-config"
			promptsCMName = "pitrigger-maxjobs-prompts"
			skillsCMName  = "pitrigger-maxjobs-skills"
		)
		var createdConfigMaps []string

		AfterEach(func() {
			for _, name := range createdConfigMaps {
				cleanupConfigMap(bgCtx, name)
			}
			cleanupConfigMap(bgCtx, promptsCMName)
			cleanupConfigMap(bgCtx, skillsCMName)
			cleanupPiTrigger(bgCtx, triggerName)
			cleanupSecret(bgCtx, secretName)

			jobList := &batchv1.JobList{}
			Expect(k8sClient.List(bgCtx, jobList, client.InNamespace(ns), client.MatchingLabels{piTriggerTriggerNameLabel: triggerName})).To(Succeed())
			for i := range jobList.Items {
				cleanupJob(bgCtx, jobList.Items[i].Name)
				cleanupConfigMap(bgCtx, jobList.Items[i].Annotations[piTriggerInputConfigMapAnnotation])
			}
		})

		It("requeues events while maxJobs is reached and resumes from the cached count", func() {
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: triggerName, Namespace: ns},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:      metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:    []string{ns},
						LabelSelector: []string{"watch=maxjobs"},
						EventType:     []triggersv1.EventType{triggersv1.EventTypeAdded},
						Concurrency:   1,
					},
					MaxJobs: 1,
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef: corev1.LocalObjectReference{Name: promptsCMName},
						SkillsConfigMapRef:  corev1.LocalObjectReference{Name: skillsCMName},
						WorkingDir:          "/workspace",
						NoExtensions:        true,
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newPiReconciler()
			nsn := types.NamespacedName{Name: triggerName, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			firstConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "pitrigger-maxjobs-first", Namespace: ns, Labels: map[string]string{"watch": "maxjobs"}},
				Data:       map[string]string{"step": "one"},
			}
			createdConfigMaps = append(createdConfigMaps, firstConfigMap.Name)
			Expect(k8sClient.Create(bgCtx, firstConfigMap)).To(Succeed())

			jobList := &batchv1.JobList{}
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.List(bgCtx, jobList, client.InNamespace(ns), client.MatchingLabels{piTriggerTriggerNameLabel: triggerName})).To(Succeed())
				g.Expect(jobList.Items).To(HaveLen(1))
			}, 10*time.Second, 200*time.Millisecond).Should(Succeed())

			secondConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "pitrigger-maxjobs-second", Namespace: ns, Labels: map[string]string{"watch": "maxjobs"}},
				Data:       map[string]string{"step": "two"},
			}
			createdConfigMaps = append(createdConfigMaps, secondConfigMap.Name)
			Expect(k8sClient.Create(bgCtx, secondConfigMap)).To(Succeed())

			Consistently(func() int {
				list := &batchv1.JobList{}
				Expect(k8sClient.List(bgCtx, list, client.InNamespace(ns), client.MatchingLabels{piTriggerTriggerNameLabel: triggerName})).To(Succeed())
				return len(list.Items)
			}, 3*time.Second, 200*time.Millisecond).Should(Equal(1))

			firstJob := &batchv1.Job{}
			Expect(k8sClient.Get(bgCtx, client.ObjectKeyFromObject(&jobList.Items[0]), firstJob)).To(Succeed())
			now := metav1.Now()
			firstJob.Status.StartTime = ptr.To(now)
			firstJob.Status.CompletionTime = ptr.To(now)
			firstJob.Status.Succeeded = 1
			firstJob.Status.Conditions = []batchv1.JobCondition{
				{Type: batchv1.JobSuccessCriteriaMet, Status: corev1.ConditionTrue, LastTransitionTime: now, Reason: batchv1.JobReasonCompletionsReached},
				{Type: batchv1.JobComplete, Status: corev1.ConditionTrue, LastTransitionTime: now, Reason: "Completed"},
			}
			Expect(k8sClient.Status().Update(bgCtx, firstJob)).To(Succeed())

			jobReconciler := &PiTriggerJobReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err = jobReconciler.Reconcile(bgCtx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(firstJob)})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				list := &batchv1.JobList{}
				g.Expect(k8sClient.List(bgCtx, list, client.InNamespace(ns), client.MatchingLabels{piTriggerTriggerNameLabel: triggerName})).To(Succeed())
				g.Expect(list.Items).To(HaveLen(2))
			}, 10*time.Second, 200*time.Millisecond).Should(Succeed())
		})
	})

	Context("PiTrigger job reconciler", func() {
		const (
			triggerName   = "pitrigger-job-status"
			secretName    = "pitrigger-job-status-agent-config"
			promptsCMName = "pitrigger-job-status-prompts"
			skillsCMName  = "pitrigger-job-status-skills"
		)
		var inputConfigMapName string

		AfterEach(func() {
			if inputConfigMapName != "" {
				cleanupConfigMap(bgCtx, inputConfigMapName)
			}
			cleanupConfigMap(bgCtx, promptsCMName)
			cleanupConfigMap(bgCtx, skillsCMName)
			cleanupJob(bgCtx, "pitrigger-job-status-job")
			cleanupPiTrigger(bgCtx, triggerName)
			cleanupSecret(bgCtx, secretName)
		})

		It("updates trigger status from completed jobs and cleans up input ConfigMaps", func() {
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: triggerName, Namespace: ns},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{Resource: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef: corev1.LocalObjectReference{Name: promptsCMName},
						SkillsConfigMapRef:  corev1.LocalObjectReference{Name: skillsCMName},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			inputConfigMapName = "pitrigger-job-status-input"
			Expect(k8sClient.Create(bgCtx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: inputConfigMapName, Namespace: ns}})).To(Succeed())

			job := &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pitrigger-job-status-job",
					Namespace: ns,
					Labels:    map[string]string{piTriggerManagedLabel: "true", piTriggerTriggerNameLabel: triggerName},
					Annotations: map[string]string{
						piTriggerInputConfigMapAnnotation:  inputConfigMapName,
						piTriggerEventTypeAnnotation:       "ADDED",
						piTriggerResourceVersionAnnotation: "42",
					},
				},
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							RestartPolicy: corev1.RestartPolicyNever,
							Containers: []corev1.Container{{
								Name:  "worker",
								Image: "docker.io/mhmxs/pi-agent-empty:latest",
							}},
						},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, job)).To(Succeed())

			storedJob := &batchv1.Job{}
			Expect(k8sClient.Get(bgCtx, client.ObjectKeyFromObject(job), storedJob)).To(Succeed())
			now := metav1.Now()
			storedJob.Status.StartTime = ptr.To(now)
			storedJob.Status.CompletionTime = ptr.To(now)
			storedJob.Status.Succeeded = 1
			storedJob.Status.Conditions = []batchv1.JobCondition{
				{Type: batchv1.JobSuccessCriteriaMet, Status: corev1.ConditionTrue, LastTransitionTime: now, Reason: batchv1.JobReasonCompletionsReached},
				{Type: batchv1.JobComplete, Status: corev1.ConditionTrue, LastTransitionTime: now, Reason: "Completed"},
			}
			Expect(k8sClient.Status().Update(bgCtx, storedJob)).To(Succeed())

			r := &PiTriggerJobReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(job)})
			Expect(err).NotTo(HaveOccurred())

			updated := &triggersv1.PiTrigger{}
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Get(bgCtx, client.ObjectKeyFromObject(trigger), updated)).To(Succeed())
				g.Expect(updated.Status.ErrorReason).To(BeEmpty())
				g.Expect(updated.Status.ErrorResourceVersion).To(BeEmpty())
			}, 5*time.Second, 100*time.Millisecond).Should(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(bgCtx, types.NamespacedName{Name: inputConfigMapName, Namespace: ns}, &corev1.ConfigMap{})
				return apierrors.IsNotFound(err)
			}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
			inputConfigMapName = ""
		})
	})

	Context("Reconcile - reports Running after watcher recovery restart", func() {
		const (
			name          = "pitrigger-recovery"
			secretName    = "pitrigger-recovery-agent-config"
			promptsCMName = "pitrigger-recovery-prompts"
			skillsCMName  = "pitrigger-recovery-skills"
		)

		AfterEach(func() {
			cleanupPiTrigger(bgCtx, name)
			cleanupConfigMap(bgCtx, promptsCMName)
			cleanupConfigMap(bgCtx, skillsCMName)
			cleanupSecret(bgCtx, secretName)
		})

		It("re-establishes the watcher, reports Running and keeps the error detail", func() {
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{Resource: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, Namespaces: []string{ns}},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef: corev1.LocalObjectReference{Name: promptsCMName},
						SkillsConfigMapRef:  corev1.LocalObjectReference{Name: skillsCMName},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newPiReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			latest := &triggersv1.PiTrigger{}
			Expect(k8sClient.Get(bgCtx, nsn, latest)).To(Succeed())
			patched := latest.DeepCopy()
			patched.Status.Phase = triggersv1.TriggerPhaseError
			patched.Status.ErrorTime = metav1.Now()
			patched.Status.ErrorReason = "job dispatch failed"
			patched.Status.ErrorResourceVersion = "42"
			Expect(k8sClient.Status().Patch(bgCtx, patched, client.MergeFrom(latest))).To(Succeed())

			r.runningTriggersLock.Lock()
			delete(r.runningTriggers, nsn.String())
			r.runningTriggersLock.Unlock()

			_, err = r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			r.runningTriggersLock.Lock()
			Expect(r.runningTriggers).To(HaveKey(nsn.String()))
			r.runningTriggersLock.Unlock()

			updated := &triggersv1.PiTrigger{}
			Expect(k8sClient.Get(bgCtx, nsn, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal(triggersv1.TriggerPhaseRunning))
			Expect(updated.Status.ErrorReason).To(Equal("job dispatch failed"))
			Expect(updated.Status.ErrorTime.IsZero()).To(BeFalse())
			Expect(updated.Status.ErrorResourceVersion).To(Equal("42"))
		})
	})

	Context("WatchInit", func() {
		const (
			name          = "pitrigger-watchinit"
			secretName    = "pitrigger-watchinit-agent-config"
			promptsCMName = "pitrigger-watchinit-prompts"
			skillsCMName  = "pitrigger-watchinit-skills"
		)

		AfterEach(func() {
			cleanupPiTrigger(bgCtx, name)
			cleanupConfigMap(bgCtx, promptsCMName)
			cleanupConfigMap(bgCtx, skillsCMName)
			cleanupSecret(bgCtx, secretName)
		})

		It("starts watchers for existing PiTrigger resources", func() {
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{Resource: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, Namespaces: []string{ns}, Concurrency: 1},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef: corev1.LocalObjectReference{Name: promptsCMName},
						SkillsConfigMapRef:  corev1.LocalObjectReference{Name: skillsCMName},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newPiReconciler()
			Expect(r.WatchInit(bgCtx)).To(Succeed())
			Eventually(func() bool {
				r.runningTriggersLock.Lock()
				defer r.runningTriggersLock.Unlock()
				_, ok := r.runningTriggers[ns+"/"+name]
				return ok
			}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
		})
	})

	Context("Reconcile - deleted trigger owner lease timeout job", func() {
		const (
			name          = "pitrigger-owner-lease-timeout"
			secretName    = "pitrigger-owner-lease-timeout-secret"
			promptsCMName = "pitrigger-owner-lease-timeout-prompts"
			skillsCMName  = "pitrigger-owner-lease-timeout-skills"
			leaseName     = "pitrigger-owner-lease-timeout-lease"
		)

		AfterEach(func() {
			jobList := &batchv1.JobList{}
			Expect(k8sClient.List(bgCtx, jobList, client.InNamespace(ns), client.MatchingLabels{piTriggerTriggerNameLabel: name})).To(Succeed())
			for i := range jobList.Items {
				cleanupJob(bgCtx, jobList.Items[i].Name)
				cleanupConfigMap(bgCtx, jobList.Items[i].Annotations[piTriggerInputConfigMapAnnotation])
			}

			trigger := &triggersv1.PiTrigger{}
			if err := k8sClient.Get(bgCtx, types.NamespacedName{Name: name, Namespace: ns}, trigger); err == nil {
				trigger.Finalizers = nil
				Expect(k8sClient.Update(bgCtx, trigger)).To(Succeed())
				Eventually(func() bool {
					err := k8sClient.Get(bgCtx, types.NamespacedName{Name: name, Namespace: ns}, &triggersv1.PiTrigger{})
					return apierrors.IsNotFound(err)
				}, 10*time.Second, 200*time.Millisecond).Should(BeTrue())
			}

			leaseObj := &coordinationv1.Lease{}
			if err := k8sClient.Get(bgCtx, types.NamespacedName{Name: leaseName, Namespace: ns}, leaseObj); err == nil {
				Expect(k8sClient.Delete(bgCtx, leaseObj)).To(Succeed())
			}
			cleanupConfigMap(bgCtx, promptsCMName)
			cleanupConfigMap(bgCtx, skillsCMName)
			cleanupSecret(bgCtx, secretName)
		})

		It("dispatches a timeout job with a timed out prompt when a deleting trigger is owned by an expired lease", func() {
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)

			renewTime := metav1.NewMicroTime(time.Now().Add(-2 * time.Minute))
			ownerLease := &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Name: leaseName, Namespace: ns},
				Spec: coordinationv1.LeaseSpec{
					LeaseDurationSeconds: ptr.To(int32(30)),
					RenewTime:            &renewTime,
				},
			}
			Expect(k8sClient.Create(bgCtx, ownerLease)).To(Succeed())

			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{
					Name:       name,
					Namespace:  ns,
					Finalizers: []string{"tests.harikube.io/cleanup"},
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: coordinationv1.SchemeGroupVersion.String(),
						Kind:       "Lease",
						Name:       ownerLease.Name,
						UID:        ownerLease.UID,
					}},
				},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{Resource: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef: corev1.LocalObjectReference{Name: promptsCMName},
						SkillsConfigMapRef:  corev1.LocalObjectReference{Name: skillsCMName},
						WorkingDir:          "/workspace",
						NoExtensions:        true,
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
			Expect(k8sClient.Delete(bgCtx, trigger)).To(Succeed())

			nsn := types.NamespacedName{Name: name, Namespace: ns}
			Eventually(func() bool {
				latest := &triggersv1.PiTrigger{}
				if err := k8sClient.Get(bgCtx, nsn, latest); err != nil {
					return false
				}
				return latest.DeletionTimestamp != nil && !latest.DeletionTimestamp.IsZero()
			}, 10*time.Second, 200*time.Millisecond).Should(BeTrue())

			r := newPiReconciler()
			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			jobList := &batchv1.JobList{}
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.List(bgCtx, jobList, client.InNamespace(ns), client.MatchingLabels{piTriggerTriggerNameLabel: name})).To(Succeed())
				g.Expect(jobList.Items).To(HaveLen(1))
			}, 10*time.Second, 200*time.Millisecond).Should(Succeed())

			job := jobList.Items[0]
			Expect(job.OwnerReferences).To(BeEmpty())
			container := job.Spec.Template.Spec.Containers[0]
			expectedPrompt, err := buildPiTriggerWorkerPrompt(trigger.Spec, fmt.Sprintf("The trigger owner lease %s timed out. Use the event payload and metadata to handle timeout cleanup for this deleted trigger.", leaseName))
			Expect(err).NotTo(HaveOccurred())
			Expect(container.Args).To(Equal(buildPiTriggerWorkerArgs(expectedPrompt, trigger.Spec.Agent)))

			inputConfigMapName := job.Annotations[piTriggerInputConfigMapAnnotation]
			inputConfigMap := &corev1.ConfigMap{}
			Expect(k8sClient.Get(bgCtx, types.NamespacedName{Name: inputConfigMapName, Namespace: ns}, inputConfigMap)).To(Succeed())
			Expect(inputConfigMap.OwnerReferences).To(BeEmpty())
			Expect(inputConfigMap.Data["event.json"]).To(ContainSubstring(`"eventType": "DELETED"`))
			Expect(inputConfigMap.Data["event.json"]).To(ContainSubstring(`owner lease ` + leaseName + ` timed out`))
			Expect(inputConfigMap.Data["event.json"]).To(ContainSubstring(job.Name))
			Expect(inputConfigMap.Data["event.json"]).To(ContainSubstring(nsn.String()))
			Expect(inputConfigMap.Data["event.json"]).To(ContainSubstring(job.Annotations[piTriggerResourceVersionAnnotation]))
			Expect(inputConfigMap.Data["metadata.json"]).To(ContainSubstring(`owner lease ` + leaseName + ` timed out`))
			Expect(inputConfigMap.Data["metadata.json"]).To(ContainSubstring(job.Name))
			Expect(inputConfigMap.Data["metadata.json"]).To(ContainSubstring(nsn.String()))
			Expect(inputConfigMap.Data["metadata.json"]).To(ContainSubstring(job.Annotations[piTriggerResourceVersionAnnotation]))
		})
	})

	Context("Reconcile - removes the watcher session when a trigger is deleted", func() {
		const (
			name          = "pitrigger-cleanup"
			secretName    = "pitrigger-cleanup-agent-config"
			promptsCMName = "pitrigger-cleanup-prompts"
			skillsCMName  = "pitrigger-cleanup-skills"
		)
		var cancelCalled atomic.Bool

		BeforeEach(func() {
			cancelCalled.Store(false)
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{Resource: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, Namespaces: []string{ns}, Concurrency: 1},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef: corev1.LocalObjectReference{Name: promptsCMName},
						SkillsConfigMapRef:  corev1.LocalObjectReference{Name: skillsCMName},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
		})

		AfterEach(func() {
			cleanupPiTrigger(bgCtx, name)
			cleanupConfigMap(bgCtx, promptsCMName)
			cleanupConfigMap(bgCtx, skillsCMName)
			cleanupSecret(bgCtx, secretName)
		})

		It("cancels and drops the running watcher when the trigger is gone (NotFound)", func() {
			r := newPiReconciler()
			nsn := types.NamespacedName{Name: name, Namespace: ns}
			key := nsn.String()

			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			r.runningTriggersLock.Lock()
			_, registered := r.runningTriggers[key]
			r.runningTriggersLock.Unlock()
			Expect(registered).To(BeTrue())

			r.runningTriggersLock.Lock()
			r.runningTriggers[key] = func() { cancelCalled.Store(true) }
			r.runningTriggersLock.Unlock()

			Expect(k8sClient.Delete(bgCtx, &triggersv1.PiTrigger{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}})).To(Succeed())
			Eventually(func() bool {
				err := k8sClient.Get(bgCtx, nsn, &triggersv1.PiTrigger{})
				return apierrors.IsNotFound(err)
			}, 10*time.Second, 500*time.Millisecond).Should(BeTrue())

			_, err = r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() bool { return cancelCalled.Load() }, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
			Eventually(func() int {
				r.runningTriggersLock.Lock()
				defer r.runningTriggersLock.Unlock()
				return len(r.runningTriggers)
			}, 10*time.Second, 100*time.Millisecond).Should(BeZero())
		})
	})

	Context("Distributed ownership", func() {
		const (
			name          = "pitrigger-unowned-partition"
			secretName    = "pitrigger-unowned-partition-agent-config"
			promptsCMName = "pitrigger-unowned-partition-prompts"
			skillsCMName  = "pitrigger-unowned-partition-skills"
		)

		BeforeEach(func() {
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)
		})

		AfterEach(func() {
			cleanupPiTrigger(bgCtx, name)
			cleanupConfigMap(bgCtx, promptsCMName)
			cleanupConfigMap(bgCtx, skillsCMName)
			cleanupSecret(bgCtx, secretName)
		})

		It("ignores trigger sessions for partitions not owned by this replica", func() {
			clientset := fake.NewSimpleClientset(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: partition.DefaultConfigMapName, Namespace: ns},
				Data: map[string]string{
					"heartbeat/pod-a":  time.Now().UTC().Format(time.RFC3339),
					"heartbeat/pod-b":  time.Now().UTC().Format(time.RFC3339),
					"partition/item-1": "pod-b",
					"partition/item-2": "pod-b",
				},
			})
			partitionController := partition.NewDistributedController(clientset, ns, "pod-a")
			Expect(partitionController.Refresh(bgCtx)).To(Succeed())

			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: ns,
					Labels:    map[string]string{partition.DistributionLabelKey: "item-99"},
				},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{Resource: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, Namespaces: []string{ns}, Concurrency: 1},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef: corev1.LocalObjectReference{Name: promptsCMName},
						SkillsConfigMapRef:  corev1.LocalObjectReference{Name: skillsCMName},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			r := newPiReconciler()
			r.PartitionController = partitionController

			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: ns}})
			Expect(err).NotTo(HaveOccurred())

			r.runningTriggersLock.Lock()
			defer r.runningTriggersLock.Unlock()
			Expect(r.runningTriggers).NotTo(HaveKey(ns + "/" + name))
		})
	})
})
