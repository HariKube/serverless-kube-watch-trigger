package controller

import (
	"fmt"
	"os"
	"time"

	"github.com/harikube/serverless-kube-watch-trigger/pkg/lease"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type triggerSessionLease struct {
	namespace      string
	name           string
	holderIdentity string
	duration       time.Duration
}

func newTriggerSessionLease(controllerName string, trigger client.Object, triggerRefName string, duration time.Duration) triggerSessionLease {
	return triggerSessionLease{
		namespace:      trigger.GetNamespace(),
		name:           triggerSessionLeaseName(controllerName, trigger),
		holderIdentity: triggerSessionHolderIdentity(controllerName, triggerRefName),
		duration:       lease.NormalizeDuration(duration),
	}
}

func triggerSessionLeaseName(controllerName string, trigger client.Object) string {
	material := fmt.Sprintf("%s/%s/%s/%s", controllerName, trigger.GetNamespace(), trigger.GetName(), trigger.GetUID())
	return fmt.Sprintf("%s-watch-%s", controllerName, shortHash(material)[:10])
}

func triggerSessionHolderIdentity(controllerName, triggerRefName string) string {
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		podName = os.Getenv("HOSTNAME")
	}
	if podName == "" {
		podName = "unknown-pod"
	}
	// Use a deterministic material based on controller and trigger reference only
	// so repeated reconciles from the same pod/controller/trigger reuse the same
	// holder identity (avoid per-call timestamps).
	material := fmt.Sprintf("%s/%s", controllerName, triggerRefName)
	return fmt.Sprintf("%s/%s/%s", podName, controllerName, shortHash(material)[:10])
}
