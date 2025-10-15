/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	triggersv1 "github.com/mhmxs/serverless-kube-watch-trigger/api/v1"
)

// OpenFaaSTriggerReconciler reconciles a OpenFaaSTrigger object
type OpenFaaSTriggerReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	runningTriggersLock sync.Mutex
	runningTriggers     map[string]func()
}

// +kubebuilder:rbac:groups=triggers.harikube.info,resources=openfaastriggers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=openfaastriggers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=triggers.harikube.info,resources=openfaastriggers/finalizers,verbs=update

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the OpenFaaSTrigger object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *OpenFaaSTriggerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = logf.FromContext(ctx)

	// TODO(user): your logic here

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OpenFaaSTriggerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.runningTriggersLock = sync.Mutex{}
	r.runningTriggers = map[string]func(){}

	return ctrl.NewControllerManagedBy(mgr).
		For(&triggersv1.OpenFaaSTrigger{}).
		Named("openfaastrigger").
		Complete(r)
}
