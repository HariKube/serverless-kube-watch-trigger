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
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	triggersv1 "github.com/mhmxs/serverless-kube-watch-trigger/api/v1"
)

var _ = Describe("HTTPTrigger Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
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
							Resource: metav1.TypeMeta{
								Kind:       "ConfigMap",
								APIVersion: "v1",
							},
						},
						HTTP: triggersv1.HTTP{
							URL: triggersv1.URL{
								Static: ptr.To("http://localhost:28736/hook"),
							},
							Method: http.MethodPost,
							Delivery: triggersv1.Delivery{
								Timeout: metav1.Duration{
									Duration: time.Second,
								},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
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

			webhookCalled := atomic.Bool{}

			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				mux := http.NewServeMux()
				mux.HandleFunc("/hook", func(w http.ResponseWriter, r *http.Request) {
					webhookCalled.Store(true)
					<-time.After(time.Second)
					cancel()
				})

				srv := &http.Server{
					Addr:    ":28736",
					Handler: mux,
				}

				go func() {
					if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						Expect(err).To(Succeed())
					}
				}()

				<-ctx.Done()
				Expect(srv.Shutdown(context.Background())).To(Succeed())
			}()

			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
			}
			Expect(k8sClient.Create(ctx, configMap)).To(Succeed())

			wg.Wait()

			Expect(webhookCalled.Load()).To(BeTrue())
		})
	})
})
