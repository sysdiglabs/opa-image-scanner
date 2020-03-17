package admissionserver

import (
	"k8s.io/api/admission/v1beta1"
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
	response, _, _ := Evaluate(admissionSpec, a.evaluator)
	return response
}
