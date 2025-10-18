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
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
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

		BeforeEach(func() {
		})

		AfterEach(func() {
			resource := &triggersv1.HTTPTrigger{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance HTTPTrigger")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("creating the secret for the Kind HTTPTrigger")
			caPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
			Expect(err).To(Succeed())
			ca := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					Organization: []string{"My CA"},
					Country:      []string{"HU"},
					CommonName:   "Root CA",
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().AddDate(1, 0, 0),
				IsCA:                  true,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				BasicConstraintsValid: true,
			}
			caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
			Expect(err).To(Succeed())
			caCert, err := x509.ParseCertificate(caBytes)
			Expect(err).To(Succeed())
			caCertPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: caCert.Raw,
			})
			serverPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
			Expect(err).To(Succeed())
			serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			Expect(err).To(Succeed())
			cert := &x509.Certificate{
				SerialNumber: serialNumber,
				Subject: pkix.Name{
					Organization: []string{"My Server"},
					Country:      []string{"HU"},
					CommonName:   "Server",
				},
				NotBefore:    time.Now(),
				NotAfter:     time.Now().AddDate(1, 0, 0),
				SubjectKeyId: []byte{1, 2, 3, 4, 6},
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				DNSNames:     []string{"localhost"},
				IPAddresses: []net.IP{
					net.ParseIP("127.0.0.1"),
				},
			}
			certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &serverPrivKey.PublicKey, caPrivKey)
			Expect(err).To(Succeed())
			serverCert, err := x509.ParseCertificate(certBytes)
			Expect(err).To(Succeed())
			serverCertPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: serverCert.Raw,
			})
			serverKeyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
			})
			clientPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
			Expect(err).To(Succeed())
			ccert := &x509.Certificate{
				SerialNumber: serialNumber,
				Subject: pkix.Name{
					Organization: []string{"My Client"},
					Country:      []string{"HU"},
					CommonName:   "Client",
				},
				NotBefore:   time.Now(),
				NotAfter:    time.Now().AddDate(1, 0, 0),
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				KeyUsage:    x509.KeyUsageDigitalSignature,
			}
			clientCertBytes, err := x509.CreateCertificate(rand.Reader, ccert, ca, &clientPrivKey.PublicKey, caPrivKey)
			Expect(err).To(Succeed())
			clientCert, err := x509.ParseCertificate(clientCertBytes)
			Expect(err).To(Succeed())
			clientCertPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: clientCert.Raw,
			})
			clientKeyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey),
			})

			triggerSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "trigger-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"password":  []byte("password"),
					"header":    []byte("header"),
					"signature": []byte("signature"),
					"ca":        caCertPEM,
					"crt":       clientCertPEM,
					"key":       clientKeyPEM,
				},
			}
			Expect(k8sClient.Create(ctx, triggerSecret)).To(Succeed())

			By("creating the custom resource for the Kind HTTPTrigger")
			httptrigger := &triggersv1.HTTPTrigger{}
			err = k8sClient.Get(ctx, typeNamespacedName, httptrigger)
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
							Namespaces:    []string{"default"},
							LabelSelector: []string{"test=true"},
							EventType: []triggersv1.EventType{
								triggersv1.EventTypeAdded,
							},
							EventFilter: `eq .new.metadata.namespace "default"`,
						},
						HTTP: triggersv1.HTTP{
							URL: triggersv1.URL{
								Template: ptr.To("https://localhost:28736/hook/{{ .metadata.name }}"),
							},
							Method: http.MethodPost,
							Auth: triggersv1.Auth{
								BasicAuth: &triggersv1.BasicAuth{
									User: "user",
									PasswordRef: corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trigger-secret",
										},
										Key: "password",
									},
								},
								TLS: &triggersv1.TLS{
									CARef: corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trigger-secret",
										},
										Key: "ca",
									},
									CertRef: corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trigger-secret",
										},
										Key: "crt",
									},
									KeyRef: corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trigger-secret",
										},
										Key: "key",
									},
									InsecureSkipVerify: true,
								},
							},
							Headers: triggersv1.Headers{
								Static: map[string]string{
									"static": "header",
								},
								Template: map[string]string{
									"template": "{{ .metadata.name }}",
								},
								FromSecretRef: map[string]corev1.SecretKeySelector{
									"header": {
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trigger-secret",
										},
										Key: "header",
									},
								},
							},
							Body: triggersv1.Body{
								Template: "{{ .metadata.name }}",
								Signature: triggersv1.Signature{
									Header: "signature",
									KeySecretRef: corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trigger-secret",
										},
										Key: "signature",
									},
									HMAC: &triggersv1.HMAC{
										HashType: triggersv1.SignatureHashTypeSHA256,
									},
								},
							},
							Delivery: triggersv1.Delivery{
								Timeout: metav1.Duration{
									Duration: time.Second,
								},
								Retries: 5,
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}

			By("creating the webhook to call")
			webhookCalled := atomic.Bool{}

			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()

				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()

				firstCall := atomic.Bool{}

				mux := http.NewServeMux()
				mux.HandleFunc("/hook/"+resourceName, func(w http.ResponseWriter, r *http.Request) {
					if !firstCall.Swap(true) {
						http.Error(w, "first call", http.StatusMethodNotAllowed)

						return
					}

					user, password, ok := r.BasicAuth()
					if !ok || user != "user" || password != "password" {
						Expect(ok).To(BeTrue())
						Expect(user).To(Equal("user"))
						Expect(password).To(Equal("password"))

						cancel()

						return
					}

					Expect(r.TLS).ToNot(BeNil())
					Expect(r.TLS.PeerCertificates[0].Subject.CommonName).To(Equal("Client"))

					body, err := io.ReadAll(r.Body)
					Expect(err).To(Succeed())
					Expect(string(body)).To(Equal(resourceName))

					hasher := hmac.New(sha256.New, []byte("signature"))
					hasher.Write(body)
					signatureBytes := hasher.Sum(nil)

					expectedHeader := map[string]string{
						"static":       "header",
						"template":     resourceName,
						"header":       "header",
						"signature":    hex.EncodeToString(signatureBytes),
						"Content-Type": "application/json",
					}
					for k, v := range expectedHeader {
						Expect(r.Header.Get(k)).To(Equal(v))
					}

					webhookCalled.Store(true)
					cancel()
				})

				serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
				Expect(err).To(Succeed())
				caCertPool := x509.NewCertPool()
				if ok := caCertPool.AppendCertsFromPEM(caCertPEM); !ok {
					log.Fatalf("Error appending client CA cert to pool")
				}
				tlsConfig := &tls.Config{
					Certificates: []tls.Certificate{serverCert},
					ClientCAs:    caCertPool,
					ClientAuth:   tls.RequireAndVerifyClientCert,
					MinVersion:   tls.VersionTLS12,
				}

				srv := &http.Server{
					Addr:      ":28736",
					Handler:   mux,
					TLSConfig: tlsConfig,
				}

				go func() {
					if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
						Expect(err).To(Succeed())
					}
				}()

				<-ctx.Done()
				Expect(srv.Shutdown(context.Background())).To(Succeed())
			}()

			By("Reconciling the created resource")
			controllerReconciler := &HTTPTriggerReconciler{
				Client:        k8sClient,
				DynamicClient: dynamicClient,
				Scheme:        k8sClient.Scheme(),

				ctx:                 context.Background(),
				runningTriggersLock: sync.Mutex{},
				runningTriggers:     map[string]func(){},
			}

			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
					Labels: map[string]string{
						"test": "true",
					},
					Annotations: map[string]string{
						"kubectl.kubernetes.io/last-applied-configuration": `{"data": []}`,
					},
				},
			}
			Expect(k8sClient.Create(ctx, configMap)).To(Succeed())

			wg.Wait()

			Expect(webhookCalled.Load()).To(BeTrue())
		})
	})
})
