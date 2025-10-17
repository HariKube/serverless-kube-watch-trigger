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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	triggersv1 "github.com/mhmxs/serverless-kube-watch-trigger/api/v1"
)

var _ = Describe("HTTPTrigger Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		openfaastrigger := &triggersv1.HTTPTrigger{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind HTTPTrigger")
			err := k8sClient.Get(ctx, typeNamespacedName, openfaastrigger)
			if err != nil && errors.IsNotFound(err) {
				resource := &triggersv1.HTTPTrigger{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: triggersv1.HTTPTriggerSpec{
						TriggerSpec: triggersv1.TriggerSpec{
							Meta: metav1.TypeMeta{
								Kind:       "Foo",
								APIVersion: "bar/v1",
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &triggersv1.HTTPTrigger{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance HTTPTrigger")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &HTTPTriggerReconciler{
				Client:        k8sClient,
				DynamicClient: dynamicClient,
				Scheme:        k8sClient.Scheme(),

				ctx:                 context.Background(),
				runningTriggersLock: sync.Mutex{},
				runningTriggers:     map[string]func(){},
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})
	})
})
