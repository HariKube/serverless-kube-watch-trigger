package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	triggersv1 "github.com/harikube/serverless-kube-watch-trigger/api/v1"
	"github.com/harikube/serverless-kube-watch-trigger/pkg/lease"
	"github.com/harikube/serverless-kube-watch-trigger/pkg/partition"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestBuildPiTriggerWorkerArgsDoesNotDisableSessions(t *testing.T) {
	args := buildPiTriggerWorkerArgs("do the thing", triggersv1.PiAgentSpec{})
	if slices.Contains(args, "--no-session") {
		t.Fatalf("expected PiTrigger worker args to preserve sessions, got %v", args)
	}
}

func TestBuildRecoverablePiTriggerWorkerPromptIncludesWakeupAndPersistInstructions(t *testing.T) {
	trigger := &triggersv1.PiTrigger{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pi-1",
			Namespace: "default",
			Labels: map[string]string{
				piTriggerSessionLabel: "session-1",
				piTriggerRoundLabel:   "2",
				piTriggerWorkerLabel:  "3",
			},
		},
	}
	prompt := buildRecoverablePiTriggerWorkerPrompt(trigger, "job-1")
	if !strings.Contains(prompt, "Session ID: session-1") {
		t.Fatalf("expected prompt to include session id, got: %s", prompt)
	}
	if !strings.Contains(prompt, "Round: 2") {
		t.Fatalf("expected prompt to include round, got: %s", prompt)
	}
	if !strings.Contains(prompt, "Worker Index: 3") {
		t.Fatalf("expected prompt to include worker index, got: %s", prompt)
	}
	if !strings.Contains(prompt, "Job: job-1") {
		t.Fatalf("expected prompt to include job name, got: %s", prompt)
	}
	// Hardening assertions: worker must be instructed to persist wake-up/session state
	if !strings.Contains(strings.ToLower(prompt), "persist") {
		t.Fatalf("expected prompt to instruct persisting wake-up/session state before exit_pi, got: %s", prompt)
	}
	// Disallow affirmative instructions that delete the session Secret before final exit/finalization on timeout/failure paths,
	// but allow explicit prohibitions (e.g., "do NOT delete it") which are protective and preserve consistency.
	low := strings.ToLower(prompt)
	if strings.Contains(low, "delete") && strings.Contains(low, "session") && strings.Contains(low, "secret") {
		// Allow negative/protective phrasings that explicitly forbid deletion.
		negatives := []string{"do not delete", "don't delete", "do not remove", "don't remove", "never delete"}
		allowed := false
		for _, n := range negatives {
			if strings.Contains(low, n) {
				allowed = true
				break
			}
		}
		if !allowed {
			t.Fatalf("prompt must not instruct deleting the session Secret before exit/finalization on timeout paths, got: %s", prompt)
		}
	}
	if !strings.Contains(prompt, "exit_pi") {
		t.Fatalf("expected prompt to mention `exit_pi` behavior on timeout/failure, got: %s", prompt)
	}
	if !strings.Contains(low, "non-zero") && !strings.Contains(low, "non zero") {
		t.Fatalf("expected prompt to instruct non-zero exit on timeout/failure, got: %s", prompt)
	}
}

func TestValidatePiAgentConfigRefs_AllowsNilOptionalConfigMaps(t *testing.T) {
	ctx := context.Background()
	secretName := "test-agent-config-nil"

	// build a local fake controller-runtime client seeded with the required Secret
	// so this plain testing.T run doesn't depend on the suite-global k8sClient
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 scheme: %v", err)
	}
	fakeClient := ctrlclientfake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: "default"},
		Data: map[string][]byte{
			"settings.json":     []byte(`{"provider":"test"}`),
			"models.json":       []byte(`[]`),
			"models-store.json": []byte(`{}`),
			"auth.json":         []byte(`{}`),
		},
	}).Build()

	agent := triggersv1.PiAgentSpec{
		ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
		PromptsConfigMapRef: nil,
		SkillsConfigMapRef:  nil,
	}

	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("validatePiAgentConfigRefs panicked: %v", r)
			}
		}()
		err = validatePiAgentConfigRefs(ctx, fakeClient, "default", agent)
	}()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestAssemblePiWorkerJob_AllowsNilOptionalConfigMaps(t *testing.T) {
	trigger := &triggersv1.PiTrigger{
		ObjectMeta: metav1.ObjectMeta{Name: "test-assemble-nil", Namespace: "default"},
		Spec: triggersv1.PiTriggerSpec{
			Agent: triggersv1.PiAgentSpec{
				Image:               "docker.io/test/pi-agent:latest",
				ConfigSecretRef:     corev1.LocalObjectReference{Name: "agent-config"},
				PromptsConfigMapRef: nil,
				SkillsConfigMapRef:  nil,
			},
		},
	}

	var job *batchv1.Job
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("assemblePiWorkerJob panicked: %v", r)
			}
		}()
		job = assemblePiWorkerJob(trigger, "job-name", map[string]string{"k": "v"}, map[string]string{"pk": "pv"}, map[string]string{"a": "b"}, []string{"arg"}, []corev1.EnvVar{}, nil, nil)
	}()

	if job == nil {
		t.Fatalf("expected non-nil Job")
	}

	foundWritableConfigVolume := false
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.Name == piTriggerPromptsVolumeName || v.Name == piTriggerSkillsVolumeName {
			t.Fatalf("did not expect prompts/skills volumes when refs are nil, found %s", v.Name)
		}
		if v.Name == piTriggerAgentConfigWritableVolumeName {
			if v.EmptyDir == nil {
				t.Fatalf("expected %s to be an EmptyDir volume", piTriggerAgentConfigWritableVolumeName)
			}
			foundWritableConfigVolume = true
		}
	}
	if !foundWritableConfigVolume {
		t.Fatalf("expected writable config volume %s", piTriggerAgentConfigWritableVolumeName)
	}
	if len(job.Spec.Template.Spec.Containers) == 0 {
		t.Fatalf("expected at least one container in the Job")
	}
	container := job.Spec.Template.Spec.Containers[0]
	foundWritableConfigMount := false
	secretFileMounts := map[string]bool{}
	for _, key := range piTriggerAgentConfigKeys {
		secretFileMounts[key] = false
	}
	for _, m := range container.VolumeMounts {
		if m.Name == piTriggerPromptsVolumeName || m.Name == piTriggerSkillsVolumeName {
			t.Fatalf("did not expect prompts/skills volume mounts when refs are nil, found %s", m.Name)
		}
		if m.Name == piTriggerAgentConfigWritableVolumeName && m.MountPath == piTriggerAgentConfigMountPath {
			foundWritableConfigMount = true
		}
		for _, key := range piTriggerAgentConfigKeys {
			if m.Name == piTriggerAgentSecretVolumeName && m.MountPath == piTriggerAgentConfigMountPath+"/"+key {
				if m.SubPath != key {
					t.Fatalf("expected subPath %q for mount %q, got %q", key, m.MountPath, m.SubPath)
				}
				if !m.ReadOnly {
					t.Fatalf("expected config secret mount %q to be read-only", m.MountPath)
				}
				secretFileMounts[key] = true
			}
		}
	}
	if !foundWritableConfigMount {
		t.Fatalf("expected writable config mount at %s", piTriggerAgentConfigMountPath)
	}
	for key, found := range secretFileMounts {
		if !found {
			t.Fatalf("expected secret file mount for %s", key)
		}
	}
}

func TestAssemblePiWorkerJob_PreservesServiceAccountName(t *testing.T) {
	trigger := &triggersv1.PiTrigger{
		ObjectMeta: metav1.ObjectMeta{Name: "test-assemble-sa", Namespace: "default"},
		Spec: triggersv1.PiTriggerSpec{
			Agent: triggersv1.PiAgentSpec{
				ServiceAccountName: "pi-agent-worker",
				ConfigSecretRef:    corev1.LocalObjectReference{Name: "agent-config"},
				Image:              "docker.io/test/pi-agent:latest",
			},
		},
	}

	job := assemblePiWorkerJob(trigger, "job-sa", map[string]string{}, map[string]string{}, map[string]string{}, []string{"arg"}, []corev1.EnvVar{}, nil, nil)
	if job == nil {
		t.Fatalf("expected non-nil Job")
	}
	if job.Spec.Template.Spec.ServiceAccountName != "pi-agent-worker" {
		t.Fatalf("expected serviceAccountName to be preserved, got %q", job.Spec.Template.Spec.ServiceAccountName)
	}
}

func findEnvVar(container corev1.Container, name string) (string, bool) {
	for _, env := range container.Env {
		if env.Name == name {
			return env.Value, true
		}
	}
	return "", false
}

func decodePiTriggerRuntimeInput(container corev1.Container) (piTriggerRuntimeInput, error) {
	encoded, ok := findEnvVar(container, piTriggerWorkerInputEnvVar)
	if !ok || strings.TrimSpace(encoded) == "" {
		return piTriggerRuntimeInput{}, fmt.Errorf("missing %s env var", piTriggerWorkerInputEnvVar)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return piTriggerRuntimeInput{}, err
	}
	var payload piTriggerRuntimeInput
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return piTriggerRuntimeInput{}, err
	}
	return payload, nil
}

func decodePiTriggerSubAgentDefaults(container corev1.Container) (piTriggerSubAgentDefaults, error) {
	encoded, ok := findEnvVar(container, piTriggerSubAgentDefaultsEnvVar)
	if !ok || strings.TrimSpace(encoded) == "" {
		return piTriggerSubAgentDefaults{}, fmt.Errorf("missing %s env var", piTriggerSubAgentDefaultsEnvVar)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return piTriggerSubAgentDefaults{}, err
	}
	var payload piTriggerSubAgentDefaults
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return piTriggerSubAgentDefaults{}, err
	}
	return payload, nil
}

// drainPiTriggerRunningTriggers stops every running trigger and clears the registry without
// invoking callback functions while holding the reconciler lock. It also waits
// briefly for any running sessions to be removed.
func drainPiTriggerRunningTriggers(r *PiTriggerReconciler) {
	r.runningTriggersLock.Lock()
	cancels := make([]func(), 0, len(r.runningTriggers))
	for _, c := range r.runningTriggers {
		cancels = append(cancels, c)
	}
	r.runningTriggers = map[string]func(){}
	r.runningTriggersLock.Unlock()

	for _, c := range cancels {
		if c != nil {
			c()
		}
	}

	// allow a short window for any watcher goroutines to remove their session
	// entries from runningTriggerSessions before tests tear down.
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.runningTriggersLock.Lock()
		sessionsEmpty := len(r.runningTriggerSessions) == 0
		r.runningTriggersLock.Unlock()
		if sessionsEmpty || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

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
		drainPiTriggerRunningTriggers(r)
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
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: "missing-prompts"}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: "missing-skills"}),
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

	Context("Session lease", func() {
		const (
			name          = "pitrigger-session-lease"
			secretName    = "pitrigger-session-secret"
			promptsCMName = "pitrigger-session-prompts"
			skillsCMName  = "pitrigger-session-skills"
		)

		AfterEach(func() {
			cleanupPiTrigger(bgCtx, name)
			cleanupConfigMap(bgCtx, promptsCMName)
			cleanupConfigMap(bgCtx, skillsCMName)
			cleanupSecret(bgCtx, secretName)
		})

		It("requeues while another replica holds the session lease using the trigger-specific lock duration", func() {
			const triggerLockDuration = 5 * time.Second
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:     metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces:   []string{ns},
						LockDuration: metav1.Duration{Duration: triggerLockDuration},
					},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: promptsCMName}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: skillsCMName}),
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			sessionLease := newTriggerSessionLease("pitrigger", trigger, ns+"/"+name, triggerLockDuration)
			leaseObj := &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Name: sessionLease.name, Namespace: ns},
				Spec: coordinationv1.LeaseSpec{
					HolderIdentity:       ptr.To("other-pod/pitrigger/external"),
					LeaseDurationSeconds: ptr.To(int32(5)),
					RenewTime:            ptr.To(metav1.NewMicroTime(time.Now().UTC())),
				},
			}
			Expect(k8sClient.Create(bgCtx, leaseObj)).To(Succeed())

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

		It("creates a durable session lease after a successful reconcile", func() {
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
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: promptsCMName}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: skillsCMName}),
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			expectedLease := newTriggerSessionLease("pitrigger", trigger, ns+"/"+name, trigger.Spec.LockDuration.Duration)
			r := newPiReconciler()

			_, err := r.Reconcile(bgCtx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: ns}})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				updated := &triggersv1.PiTrigger{}
				g.Expect(k8sClient.Get(bgCtx, types.NamespacedName{Name: name, Namespace: ns}, updated)).To(Succeed())
				g.Expect(updated.Status.Phase).To(Equal(triggersv1.TriggerPhaseRunning))
				leaseObj := &coordinationv1.Lease{}
				g.Expect(k8sClient.Get(bgCtx, types.NamespacedName{Name: expectedLease.name, Namespace: ns}, leaseObj)).To(Succeed())
				g.Expect(leaseObj.Spec.HolderIdentity).NotTo(BeNil())
			}, 5*time.Second, 100*time.Millisecond).Should(Succeed())
		})

		It("clears a stale legacy annotation lease even when the trigger is already running", func() {
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
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: promptsCMName}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: skillsCMName}),
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

	Context("Session lease coordination", func() {
		It("does not start a watcher session from WatchInit while another replica holds the session lease", func() {
			const (
				name          = "pitrigger-watchinit-active-session-lease"
				secretName    = "pitrigger-watchinit-active-session-secret"
				promptsCMName = "pitrigger-watchinit-active-session-prompts"
				skillsCMName  = "pitrigger-watchinit-active-session-skills"
			)
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)
			DeferCleanup(func() {
				cleanupPiTrigger(bgCtx, name)
				cleanupConfigMap(bgCtx, promptsCMName)
				cleanupConfigMap(bgCtx, skillsCMName)
				cleanupSecret(bgCtx, secretName)
			})

			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{
						Resource:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
						Namespaces: []string{ns},
					},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: promptsCMName}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: skillsCMName}),
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			sessionLease := newTriggerSessionLease("pitrigger", trigger, ns+"/"+name, trigger.Spec.LockDuration.Duration)
			leaseObj := &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Name: sessionLease.name, Namespace: ns},
				Spec: coordinationv1.LeaseSpec{
					HolderIdentity:       ptr.To("other-pod/pitrigger/external"),
					LeaseDurationSeconds: ptr.To(int32(30)),
					RenewTime:            ptr.To(metav1.NewMicroTime(time.Now().UTC())),
				},
			}
			Expect(k8sClient.Create(bgCtx, leaseObj)).To(Succeed())

			r := newPiReconciler()
			Expect(r.WatchInit(bgCtx)).To(Succeed())

			r.runningTriggersLock.Lock()
			defer r.runningTriggersLock.Unlock()
			Expect(r.runningTriggers).NotTo(HaveKey(ns + "/" + name))
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
			triggerName       = "pitrigger-success"
			configMapName     = "pitrigger-configmap"
			secretName        = "pitrigger-agent-config"
			sessionSecretName = "pitrigger-session-secret"
			promptsCMName     = "pitrigger-agent-prompts"
			skillsCMName      = "pitrigger-agent-skills"
		)

		AfterEach(func() {
			cleanupConfigMap(bgCtx, configMapName)
			cleanupConfigMap(bgCtx, promptsCMName)
			cleanupConfigMap(bgCtx, skillsCMName)
			cleanupPiTrigger(bgCtx, triggerName)
			cleanupSecret(bgCtx, sessionSecretName)
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
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: latePromptsName}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: lateSkillsName}),
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
		})

		It("renders prompt input and creates a worker Job per event", func() {
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigSecret(bgCtx, sessionSecretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)
			backoffLimit := int32(4)
			ttlSeconds := int32(300)
			workerTimeout := metav1.Duration{Duration: 7 * time.Minute}
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{
					Name:      triggerName,
					Namespace: ns,
					Labels: map[string]string{
						piTriggerSessionLabel: "session-success",
						piTriggerRoundLabel:   "4",
						piTriggerWorkerLabel:  "2",
					},
					Annotations: map[string]string{piTriggerSessionSecretAnnotation: sessionSecretName},
				},
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
						PromptsConfigMapRef:     ptr.To(corev1.LocalObjectReference{Name: promptsCMName}),
						SkillsConfigMapRef:      ptr.To(corev1.LocalObjectReference{Name: skillsCMName}),
						Provider:                "openai",
						Model:                   "gpt-4o-mini",
						WorkingDir:              "/workspace",
						NoExtensions:            true,
						Extensions:              []string{"npm:pi-graft", "npm:custom-tool"},
						Timeout:                 workerTimeout,
						ServiceAccountName:      "pi-agent-worker",
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
			Expect(job.OwnerReferences).To(HaveLen(1))
			Expect(job.OwnerReferences[0].APIVersion).To(Equal("v1"))
			Expect(job.OwnerReferences[0].Kind).To(Equal("Secret"))
			Expect(job.OwnerReferences[0].Name).To(Equal(sessionSecretName))
			Expect(job.OwnerReferences[0].Controller).NotTo(BeNil())
			Expect(*job.OwnerReferences[0].Controller).To(BeTrue())
			Expect(job.Spec.BackoffLimit).NotTo(BeNil())
			Expect(*job.Spec.BackoffLimit).To(Equal(backoffLimit))
			Expect(job.Spec.TTLSecondsAfterFinished).NotTo(BeNil())
			Expect(*job.Spec.TTLSecondsAfterFinished).To(Equal(ttlSeconds))
			Expect(job.Spec.ActiveDeadlineSeconds).NotTo(BeNil())
			Expect(*job.Spec.ActiveDeadlineSeconds).To(Equal(int64(420)))
			Expect(job.Spec.Template.Spec.ServiceAccountName).To(Equal("pi-agent-worker"))
			Expect(job.Spec.Template.Spec.Volumes).To(HaveLen(4))
			Expect(job.Spec.Template.Spec.Volumes[0].EmptyDir).NotTo(BeNil())
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
			expectedPrompt := buildRecoverablePiTriggerWorkerPrompt(trigger, job.Name)
			Expect(expectedPrompt).To(ContainSubstring("Session ID: session-success"))
			Expect(expectedPrompt).To(ContainSubstring("Round: 4"))
			Expect(expectedPrompt).To(ContainSubstring("Worker Index: 2"))
			Expect(expectedPrompt).To(ContainSubstring("Job: " + job.Name))
			Expect(expectedPrompt).To(ContainSubstring("pi-trigger-runtime-input"))
			Expect(expectedPrompt).To(ContainSubstring("pi-subagent-defaults-runtime"))
			Expect(container.Args).To(Equal(buildPiTriggerWorkerArgs(expectedPrompt, trigger.Spec.Agent)))
			promptArg := container.Args[len(container.Args)-1]
			promptParts := strings.SplitN(promptArg, "Prompt: ", 2)
			Expect(promptParts).To(HaveLen(2))
			Expect(promptParts[1]).To(Equal(expectedPrompt))
			Expect(container.WorkingDir).To(Equal("/workspace"))
			Expect(container.Env).To(ContainElement(corev1.EnvVar{Name: "HOME", Value: piTriggerWorkerHomeDir}))
			Expect(container.Env).To(ContainElement(corev1.EnvVar{Name: "EXTRA_FLAG", Value: "true"}))
			Expect(container.Args).To(ContainElement(piTriggerRuntimeExtensionPath))
			Expect(container.Args).To(ContainElement(piTriggerTimeoutDiagnosticsExtensionPath))
			Expect(container.Args).To(ContainElement(piTriggerServiceDiscoveryExtensionPath))
			Expect(container.VolumeMounts).To(ContainElement(corev1.VolumeMount{Name: piTriggerAgentConfigWritableVolumeName, MountPath: piTriggerAgentConfigMountPath}))
			for _, key := range piTriggerAgentConfigKeys {
				Expect(container.VolumeMounts).To(ContainElement(corev1.VolumeMount{Name: piTriggerAgentSecretVolumeName, MountPath: piTriggerAgentConfigMountPath + "/" + key, SubPath: key, ReadOnly: true}))
			}
			Expect(container.VolumeMounts).To(ContainElement(corev1.VolumeMount{Name: piTriggerPromptsVolumeName, MountPath: piTriggerAgentPromptsMountPath, ReadOnly: true}))
			Expect(container.VolumeMounts).To(ContainElement(corev1.VolumeMount{Name: piTriggerSkillsVolumeName, MountPath: piTriggerAgentSkillsMountPath, ReadOnly: true}))

			runtimeInput, err := decodePiTriggerRuntimeInput(container)
			Expect(err).NotTo(HaveOccurred())
			Expect(runtimeInput.Metadata.EventType).To(Equal("ADDED"))
			Expect(runtimeInput.Metadata.TriggerName).To(Equal("pitrigger-success"))
			subAgentDefaults, err := decodePiTriggerSubAgentDefaults(container)
			Expect(err).NotTo(HaveOccurred())
			Expect(subAgentDefaults.Namespace).To(Equal(ns))
			Expect(subAgentDefaults.Agent.Image).To(Equal(trigger.Spec.Agent.Image))

			// session labels should be propagated to the Job and runtime metadata
			Expect(job.Labels[piTriggerSessionLabel]).To(Equal("session-success"))
			Expect(job.Labels[piTriggerRoundLabel]).To(Equal("4"))
			Expect(job.Labels[piTriggerWorkerLabel]).To(Equal("2"))
			Expect(job.Labels[piTriggerTraceIDLabel]).NotTo(BeEmpty())
			Expect(job.Spec.Template.Labels[piTriggerTraceIDLabel]).To(Equal(job.Labels[piTriggerTraceIDLabel]))
			Expect(subAgentDefaults.TraceID).To(Equal(job.Labels[piTriggerTraceIDLabel]))
			Expect(runtimeInput.Metadata.TraceID).To(Equal(job.Labels[piTriggerTraceIDLabel]))

			// runtime metadata should include structured session/job identity values useful for wake-up
			Expect(runtimeInput.Metadata.SessionID).To(Equal("session-success"))
			Expect(runtimeInput.Metadata.Round).To(Equal("4"))
			Expect(runtimeInput.Metadata.WorkerIndex).To(Equal("2"))
			Expect(runtimeInput.Metadata.SessionSecretName).To(Equal(sessionSecretName))
			Expect(runtimeInput.Metadata.JobName).To(Equal(job.Name))
			managedConfigMaps := &corev1.ConfigMapList{}
			Expect(k8sClient.List(bgCtx, managedConfigMaps, client.InNamespace(ns), client.MatchingLabels{piTriggerManagedLabel: "true"})).To(Succeed())
			Expect(managedConfigMaps.Items).To(BeEmpty())

			cleanupJob(bgCtx, job.Name)
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
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: promptsCMName}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: skillsCMName}),
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

		AfterEach(func() {
			cleanupConfigMap(bgCtx, promptsCMName)
			cleanupConfigMap(bgCtx, skillsCMName)
			cleanupJob(bgCtx, "pitrigger-job-status-job")
			cleanupPiTrigger(bgCtx, triggerName)
			cleanupSecret(bgCtx, secretName)
		})

		It("updates trigger status from completed jobs without extra input cleanup objects", func() {
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigMaps(bgCtx, promptsCMName, skillsCMName)
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{Name: triggerName, Namespace: ns},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{Resource: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: secretName},
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: promptsCMName}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: skillsCMName}),
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())

			job := &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pitrigger-job-status-job",
					Namespace: ns,
					Labels:    map[string]string{piTriggerManagedLabel: "true", piTriggerTriggerNameLabel: triggerName},
					Annotations: map[string]string{
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
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: promptsCMName}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: skillsCMName}),
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

			r.stopRunningTrigger(nsn.String())
			sessionLease := newTriggerSessionLease("pitrigger", trigger, nsn.String(), trigger.Spec.LockDuration.Duration)
			Eventually(func() bool {
				err := k8sClient.Delete(bgCtx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: sessionLease.name, Namespace: ns}})
				return err == nil || apierrors.IsNotFound(err)
			}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())

			Eventually(func(g Gomega) {
				_, err = r.Reconcile(bgCtx, reconcile.Request{NamespacedName: nsn})
				g.Expect(err).NotTo(HaveOccurred())

				r.runningTriggersLock.Lock()
				defer r.runningTriggersLock.Unlock()
				g.Expect(r.runningTriggers).To(HaveKey(nsn.String()))

				updated := &triggersv1.PiTrigger{}
				g.Expect(k8sClient.Get(bgCtx, nsn, updated)).To(Succeed())
				g.Expect(updated.Status.Phase).To(Equal(triggersv1.TriggerPhaseRunning))
				g.Expect(updated.Status.ErrorReason).To(Equal("job dispatch failed"))
				g.Expect(updated.Status.ErrorTime.IsZero()).To(BeFalse())
				g.Expect(updated.Status.ErrorResourceVersion).To(Equal("42"))
			}, 10*time.Second, 200*time.Millisecond).Should(Succeed())
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
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: promptsCMName}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: skillsCMName}),
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
			name              = "pitrigger-owner-lease-timeout"
			secretName        = "pitrigger-owner-lease-timeout-secret"
			sessionSecretName = "pitrigger-owner-lease-timeout-session"
			promptsCMName     = "pitrigger-owner-lease-timeout-prompts"
			skillsCMName      = "pitrigger-owner-lease-timeout-skills"
			leaseName         = "pitrigger-owner-lease-timeout-lease"
		)

		AfterEach(func() {
			jobList := &batchv1.JobList{}
			Expect(k8sClient.List(bgCtx, jobList, client.InNamespace(ns), client.MatchingLabels{piTriggerTriggerNameLabel: name})).To(Succeed())
			for i := range jobList.Items {
				cleanupJob(bgCtx, jobList.Items[i].Name)
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
			cleanupSecret(bgCtx, sessionSecretName)
			cleanupSecret(bgCtx, secretName)
		})

		It("dispatches a timeout job with a timed out prompt when a deleting trigger is owned by an expired lease", func() {
			createPiAgentConfigSecret(bgCtx, secretName)
			createPiAgentConfigSecret(bgCtx, sessionSecretName)
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
					Labels: map[string]string{
						piTriggerSessionLabel: "session-timeout",
						piTriggerRoundLabel:   "7",
						piTriggerWorkerLabel:  "1",
					},
					Annotations: map[string]string{piTriggerSessionSecretAnnotation: sessionSecretName},
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
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: promptsCMName}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: skillsCMName}),
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
			Expect(job.OwnerReferences).To(HaveLen(1))
			Expect(job.OwnerReferences[0].APIVersion).To(Equal("v1"))
			Expect(job.OwnerReferences[0].Kind).To(Equal("Secret"))
			Expect(job.OwnerReferences[0].Name).To(Equal(sessionSecretName))
			Expect(job.OwnerReferences[0].Controller).NotTo(BeNil())
			Expect(*job.OwnerReferences[0].Controller).To(BeTrue())
			Expect(job.Spec.TTLSecondsAfterFinished).NotTo(BeNil())
			Expect(*job.Spec.TTLSecondsAfterFinished).To(Equal(int32(86400)))
			Expect(job.Spec.ActiveDeadlineSeconds).To(BeNil())
			container := job.Spec.Template.Spec.Containers[0]
			expectedPrompt := buildRecoverablePiTriggerWorkerPrompt(trigger, job.Name, fmt.Sprintf("TIMED_OUT: The trigger owner lease %s timed out. Use the payload and metadata to handle timeout cleanup for this deleted trigger.", leaseName))
			Expect(expectedPrompt).To(ContainSubstring("TIMED_OUT"))
			Expect(expectedPrompt).To(ContainSubstring(fmt.Sprintf("owner lease %s timed out", leaseName)))
			Expect(expectedPrompt).To(ContainSubstring("Session ID: session-timeout"))
			Expect(expectedPrompt).To(ContainSubstring("Round: 7"))
			Expect(expectedPrompt).To(ContainSubstring("Worker Index: 1"))
			Expect(expectedPrompt).To(ContainSubstring("Job: " + job.Name))
			Expect(container.Args).To(Equal(buildPiTriggerWorkerArgs(expectedPrompt, trigger.Spec.Agent)))

			runtimeInput, err := decodePiTriggerRuntimeInput(container)
			Expect(err).NotTo(HaveOccurred())
			payloadJSON, err := json.Marshal(runtimeInput)
			Expect(err).NotTo(HaveOccurred())
			payloadText := string(payloadJSON)
			// Assert structured metadata (event/session/job identity and timeout message) comes from Metadata
			Expect(runtimeInput.Metadata.EventType).To(Equal("DELETED"))
			Expect(runtimeInput.Metadata.Message).To(ContainSubstring(fmt.Sprintf("owner lease %s timed out", leaseName)))
			Expect(runtimeInput.Metadata.JobName).To(Equal(job.Name))
			Expect(runtimeInput.Metadata.ResourceVersion).To(Equal(job.Annotations[piTriggerResourceVersionAnnotation]))
			// Assert the payload is the raw triggering object and contains normal k8s fields
			if objMeta, ok := runtimeInput.Payload["metadata"].(map[string]interface{}); ok {
				Expect(objMeta["name"]).To(Equal(name))
				Expect(objMeta["namespace"]).To(Equal(ns))
			} else {
				// fallback: ensure the serialized payload contains a namespace/name reference
				Expect(payloadText).To(ContainSubstring(nsn.String()))
			}

			// session labels and metadata should be present for deterministic wake-up/restore
			Expect(job.Labels[piTriggerSessionLabel]).To(Equal("session-timeout"))
			Expect(job.Labels[piTriggerRoundLabel]).To(Equal("7"))
			Expect(job.Labels[piTriggerWorkerLabel]).To(Equal("1"))
			Expect(job.Labels[piTriggerTraceIDLabel]).NotTo(BeEmpty())
			Expect(job.Spec.Template.Labels[piTriggerTraceIDLabel]).To(Equal(job.Labels[piTriggerTraceIDLabel]))
			Expect(runtimeInput.Metadata.TraceID).To(Equal(job.Labels[piTriggerTraceIDLabel]))
			Expect(runtimeInput.Metadata.SessionID).To(Equal("session-timeout"))
			Expect(runtimeInput.Metadata.Round).To(Equal("7"))
			Expect(runtimeInput.Metadata.WorkerIndex).To(Equal("1"))
			Expect(runtimeInput.Metadata.SessionSecretName).To(Equal(sessionSecretName))
		})

		// Regression test: when a trigger has already exceeded spec.timeout before the first
		// reconcile and is already in finalizer-protected deletion state, reconcile must
		// dispatch a session-timeout worker job with a DELETED event payload/metadata instead
		// of skipping dispatch.
		It("dispatches a session timeout job for an already-expired, deleting trigger", func() {
			const (
				expiredTriggerName   = "pitrigger-expired-session-regression"
				expiredSecretName    = "pitrigger-expired-agent-config"
				expiredSessionSecret = "pitrigger-expired-session-secret"
				expiredPromptsName   = "pitrigger-expired-prompts"
				expiredSkillsName    = "pitrigger-expired-skills"
			)

			DeferCleanup(func() {
				jobList := &batchv1.JobList{}
				_ = k8sClient.List(bgCtx, jobList, client.InNamespace(ns), client.MatchingLabels{piTriggerTriggerNameLabel: expiredTriggerName})
				for i := range jobList.Items {
					cleanupJob(bgCtx, jobList.Items[i].Name)
				}
				cleanupConfigMap(bgCtx, expiredPromptsName)
				cleanupConfigMap(bgCtx, expiredSkillsName)
				cleanupPiTrigger(bgCtx, expiredTriggerName)
				cleanupSecret(bgCtx, expiredSessionSecret)
				cleanupSecret(bgCtx, expiredSecretName)
			})

			createPiAgentConfigSecret(bgCtx, expiredSecretName)
			createPiAgentConfigSecret(bgCtx, expiredSessionSecret)
			createPiAgentConfigMaps(bgCtx, expiredPromptsName, expiredSkillsName)

			// create the trigger with a short timeout and an old creation timestamp so the
			// session is already expired before reconcile runs. Keep a finalizer so the
			// resource remains in a deleting state.
			trigger := &triggersv1.PiTrigger{
				ObjectMeta: metav1.ObjectMeta{
					Name:       expiredTriggerName,
					Namespace:  ns,
					Finalizers: []string{"tests.harikube.io/cleanup"},
					Labels: map[string]string{
						piTriggerSessionLabel: "session-expired",
						piTriggerRoundLabel:   "1",
						piTriggerWorkerLabel:  "0",
					},
					Annotations:       map[string]string{piTriggerSessionSecretAnnotation: expiredSessionSecret},
					CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Minute)),
				},
				Spec: triggersv1.PiTriggerSpec{
					TriggerSpec: triggersv1.TriggerSpec{Resource: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
					Agent: triggersv1.PiAgentSpec{
						Image:               "docker.io/mhmxs/pi-agent-empty:latest",
						ConfigSecretRef:     corev1.LocalObjectReference{Name: expiredSecretName},
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: expiredPromptsName}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: expiredSkillsName}),
						Timeout:             metav1.Duration{Duration: 1 * time.Second},
					},
				},
			}
			Expect(k8sClient.Create(bgCtx, trigger)).To(Succeed())
			Expect(k8sClient.Delete(bgCtx, trigger)).To(Succeed())

			nsn := types.NamespacedName{Name: expiredTriggerName, Namespace: ns}
			Eventually(func() bool {
				latest := &triggersv1.PiTrigger{}
				if err := k8sClient.Get(bgCtx, nsn, latest); err != nil {
					return false
				}
				return latest.DeletionTimestamp != nil && !latest.DeletionTimestamp.IsZero()
			}, 10*time.Second, 200*time.Millisecond).Should(BeTrue())

			r := newPiReconciler()

			// Exercise the deletion-path logic using an in-memory trigger whose CreationTimestamp
			// is explicitly old enough to exceed spec.timeout while keeping the persisted
			// deleting/finalizer state in the API server for owner refs and cleanup.
			latest := &triggersv1.PiTrigger{}
			Expect(k8sClient.Get(bgCtx, nsn, latest)).To(Succeed())
			inMem := latest.DeepCopy()
			// ensure the in-memory trigger appears old enough to have its session timed out
			inMem.CreationTimestamp = metav1.NewTime(time.Now().Add(-2 * time.Minute))
			// keep the DeletionTimestamp from the persisted object
			inMem.DeletionTimestamp = latest.DeletionTimestamp

			// Exercise the non-swallowing timeout helper directly for a deleting trigger
			// using an in-memory copy so the test fails immediately on helper error.
			err := r.dispatchTriggerSessionTimeoutJob(bgCtx, ns+"/"+expiredTriggerName, inMem)
			Expect(err).NotTo(HaveOccurred())

			jobList := &batchv1.JobList{}
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.List(bgCtx, jobList, client.InNamespace(ns), client.MatchingLabels{piTriggerTriggerNameLabel: expiredTriggerName})).To(Succeed())
				g.Expect(jobList.Items).To(HaveLen(1))
			}, 10*time.Second, 200*time.Millisecond).Should(Succeed())

			job := jobList.Items[0]
			container := job.Spec.Template.Spec.Containers[0]
			runtimeInput, err := decodePiTriggerRuntimeInput(container)
			Expect(err).NotTo(HaveOccurred())
			payloadJSON, err := json.Marshal(runtimeInput)
			Expect(err).NotTo(HaveOccurred())
			payloadText := string(payloadJSON)
			// Assert structured metadata (event/session/job identity and timeout message) comes from Metadata
			Expect(runtimeInput.Metadata.EventType).To(Equal("DELETED"))
			Expect(runtimeInput.Metadata.Message).To(ContainSubstring("trigger session timed out"))
			Expect(runtimeInput.Metadata.JobName).To(Equal(job.Name))
			Expect(runtimeInput.Metadata.ResourceVersion).To(Equal(job.Annotations[piTriggerResourceVersionAnnotation]))
			// Assert the payload is the raw triggering object and contains normal k8s fields
			if objMeta, ok := runtimeInput.Payload["metadata"].(map[string]interface{}); ok {
				Expect(objMeta["name"]).To(Equal(expiredTriggerName))
				Expect(objMeta["namespace"]).To(Equal(ns))
			} else {
				// fallback: ensure the serialized payload contains a namespace/name reference
				Expect(payloadText).To(ContainSubstring(nsn.String()))
			}

			// session identity should be preserved in labels/metadata for restore
			Expect(job.Labels[piTriggerSessionLabel]).To(Equal("session-expired"))
			Expect(job.Labels[piTriggerRoundLabel]).To(Equal("1"))
			Expect(job.Labels[piTriggerWorkerLabel]).To(Equal("0"))
			Expect(job.Labels[piTriggerTraceIDLabel]).NotTo(BeEmpty())
			Expect(job.Spec.Template.Labels[piTriggerTraceIDLabel]).To(Equal(job.Labels[piTriggerTraceIDLabel]))
			Expect(runtimeInput.Metadata.TraceID).To(Equal(job.Labels[piTriggerTraceIDLabel]))
			Expect(runtimeInput.Metadata.SessionID).To(Equal("session-expired"))
			Expect(runtimeInput.Metadata.Round).To(Equal("1"))
			Expect(runtimeInput.Metadata.WorkerIndex).To(Equal("0"))
			// when the trigger is deleting, the session secret should directly own the worker Job
			Expect(job.OwnerReferences).ToNot(BeEmpty())
			Expect(job.OwnerReferences[0].Kind).To(Equal("Secret"))
			Expect(job.OwnerReferences[0].Name).To(Equal(expiredSessionSecret))

			// trigger must still be in deleting state and retain the finalizer so cleanup can proceed
			latest = &triggersv1.PiTrigger{}
			Expect(k8sClient.Get(bgCtx, nsn, latest)).To(Succeed())
			Expect(latest.DeletionTimestamp).NotTo(BeNil())
			Expect(latest.Finalizers).To(ContainElement("tests.harikube.io/cleanup"))
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
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: promptsCMName}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: skillsCMName}),
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
						PromptsConfigMapRef: ptr.To(corev1.LocalObjectReference{Name: promptsCMName}),
						SkillsConfigMapRef:  ptr.To(corev1.LocalObjectReference{Name: skillsCMName}),
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
