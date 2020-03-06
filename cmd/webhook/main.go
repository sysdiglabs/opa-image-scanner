/*
Copyright 2018 The Kubernetes Authors.

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

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"k8s.io/api/admission/v1beta1"

	"k8s.io/klog"

	"sync"

	"image-scan-webhook/pkg/anchore"
	"image-scan-webhook/pkg/opa"

	genericadmissionserver "github.com/openshift/generic-admission-server/pkg/cmd"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

const opaRulesFile = "/tmp/image-scan/rules.rego"

const regoFileDefault string = `
package imageadmission

deny_image[msg] {
	msg := "No rules defined. Please define 'imageadmission' package with deny_image[msg] rules"
}
`

type admissionHook struct {
	reservationClient dynamic.ResourceInterface
	lock              sync.RWMutex
	initialized       bool
}

// toAdmissionResponse is a helper function to create an AdmissionResponse
// with an embedded error
func toAdmissionResponse(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

func (a *admissionHook) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	klog.Info("Initializing handler")

	return nil
}

func (a *admissionHook) ValidatingResource() (plural schema.GroupVersionResource, singular string) {
	klog.Info("ValidatingResource handler")

	return schema.GroupVersionResource{
		Group:    "admission.sysdig.com",
		Version:  "v1beta1",
		Resource: "imagechecks",
	}, "imagecheck"

}

type OPAInput struct {
	ScanReport       *anchore.ScanReport
	AdmissionRequest *v1beta1.AdmissionRequest
}

func (a *admissionHook) Validate(admissionSpec *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {
	klog.Info("Verifying Pod admission request")

	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	if admissionSpec.Resource != podResource {
		err := fmt.Errorf("expect resource to be %s", podResource)
		klog.Error(err)
		return toAdmissionResponse(err)
	}

	raw := admissionSpec.Object.Raw
	pod := corev1.Pod{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, &pod); err != nil {
		klog.Error(err)
		return toAdmissionResponse(err)
	}

	reviewResponse := v1beta1.AdmissionResponse{}
	reviewResponse.Allowed = true

	for _, container := range pod.Spec.Containers {
		image := container.Image

		client, err := newAnchoreClient()
		if err != nil {
			klog.Errorf("Error creating Image Scan client: %v", err)
			//TODO: Evaluate error with OPA
		} else {
			klog.Info("Checking image: " + image)

			result, err := client.GetScanReport(image)
			if err != nil {
				klog.Warningf("Get image scan result error: %v", err)
			} else {
				klog.Info("Evaluating scan report with OPA")
				opaInput := OPAInput{result, admissionSpec}

				regoFile := readOpaRules()

				err := opa.Evaluate(regoFile, opaInput)
				if err != nil {
					reviewResponse.Allowed = false
					msg := fmt.Sprintf("Image failed policy check: %s. Error: %v", image, err)
					reviewResponse.Result = &metav1.Status{Message: msg}
					klog.Warning(msg)
					return &reviewResponse
				}
			}
		}
	}

	klog.Info("Pod accepted: " + pod.Name)
	return &reviewResponse
}

func newAnchoreClient() (*anchore.AnchoreClient, error) {
	baseUrl := strings.TrimSpace(os.Getenv("SYSDIG_SECURE_URL"))
	if baseUrl == "" {
		return nil, fmt.Errorf("Environment variable SYSDIG_SECURE_URL is not defined")
	}
	token := strings.TrimSpace(os.Getenv("SYSDIG_SECURE_TOKEN"))
	if token == "" {
		return nil, fmt.Errorf("Environment variable SYSDIG_SECURE_TOKEN is not defined")
	}
	return anchore.NewClient(baseUrl, token)
}

func readOpaRules() string {
	regoFileContents, err := ioutil.ReadFile(opaRulesFile)
	if err != nil {
		return regoFileDefault
	} else {
		return string(regoFileContents)
	}

}

func main() {
	klog.Infof("Starting generic admission server...")

	genericadmissionserver.RunAdmissionServer(&admissionHook{})

	klog.Info("Exiting...")
}
