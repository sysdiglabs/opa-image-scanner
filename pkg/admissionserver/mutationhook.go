package admissionserver

import (
	"fmt"
	"strings"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
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
		Resource: "imagechecks",
	}, "imagemutation"

}

func (m *mutationHook) Admit(admissionSpec *v1beta1.AdmissionRequest) *v1beta1.AdmissionResponse {
	klog.Info("[mutation-server] mutating Pod admission request")
	response, digestMapping, pod := Evaluate(admissionSpec, m.evaluator)

	p := v1beta1.PatchType("JSONPatch")
	response.PatchType = &p

	response.Patch = []byte(buildJSONPatch(admissionSpec, pod, digestMapping))

	return response
}

func buildJSONPatch(admissionSpec *v1beta1.AdmissionRequest, pod *corev1.Pod, digestMapping map[string]string) string {

	if pod == nil {
		return "[]"

	}
	var sb strings.Builder
	for idx, container := range pod.Spec.Containers {

		if strings.Contains(container.Image, "@sha256:") {
			continue
		}

		if sb.Len() != 0 {
			sb.WriteString(",")
		}
		parts := strings.Split(container.Image, ":")
		newImage := fmt.Sprintf("%s@%s", parts[0], digestMapping[container.Image])
		sb.WriteString(fmt.Sprintf(`{ "op": "replace", "path": "/spec/containers/%d/image", "value": "%s" },`, idx, newImage))
		sb.WriteString(fmt.Sprintf(`{ "op": "add", "path": "/metadata/annotations", "value": {"admission.sysdig.com/container-%d-original-image": "%s", "admission.sysdig.com/container-%d-mutated-image": "%s"  }}`, idx+1, container.Image, idx+1, newImage))

		klog.Infof("[mutation-server] Patching container image: %s -> %s", container.Image, newImage)

	}

	return "[" + sb.String() + "]"
}
