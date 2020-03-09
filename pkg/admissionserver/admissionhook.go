package admissionserver

import (
	"fmt"
	"strings"

	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
)

func (a *admissionHook) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	klog.Info("[admission-server] Initializing handler")
	return nil
}

func (a *admissionHook) ValidatingResource() (plural schema.GroupVersionResource, singular string) {
	klog.Info("[admission-server] ValidatingResource handler")

	return schema.GroupVersionResource{
		Group:    "admission.sysdig.com",
		Version:  "v1beta1",
		Resource: "imagechecks",
	}, "imagecheck"

}

func (a *admissionHook) Validate(admissionSpec *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {
	klog.Info("[admission-server] validating Pod admission request")

	if err := validatePod(admissionSpec); err != nil {
		klog.Errorf("[admission-server] %v", err)
		return toAdmissionResponse(err)
	} else {

		klog.Info("[admission-server] evaluating admission of pod: " + admissionSpec.Name)

		allowed, denyReasons := a.evaluator.Evaluate(admissionSpec)

		if allowed {
			klog.Infof("[admission-server] pod accepted: %s", admissionSpec.Name)
			return &v1beta1.AdmissionResponse{Allowed: true}
		} else {
			reasons := strings.Join(denyReasons, "\n")

			klog.Infof("[admission-server] pod rejected: %s. Reasons:\n%s", admissionSpec.Name, reasons)

			//TODO: More info? Annotations?
			reviewResponse := v1beta1.AdmissionResponse{}
			reviewResponse.Allowed = false
			reviewResponse.Result = &metav1.Status{Message: reasons}
			return &reviewResponse
		}
	}

}

func validatePod(admissionSpec *v1beta1.AdmissionRequest) error {
	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	if admissionSpec.Resource != podResource {
		return fmt.Errorf("expected resource to be %s", podResource)
	}

	return nil
}
