package admissionserver

import (
	"k8s.io/api/admission/v1beta1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
)

func (m *mutationHook) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	klog.Info("[mutation-server] Initializing handler")
	return nil
}

func (m *mutationHook) MutatingResource() (plural schema.GroupVersionResource, singular string) {
	klog.Info("[mutation-server] MutatingResource handler")

	return schema.GroupVersionResource{
		Group:    "admission.sysdig.com",
		Version:  "v1beta1",
		Resource: "imagemutations",
	}, "imagemutation"

}

func (m *mutationHook) Admit(admissionSpec *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {
	klog.Info("[mutation-server] mutating Pod admission request")
	return &v1beta1.AdmissionResponse{Allowed: true}
}
