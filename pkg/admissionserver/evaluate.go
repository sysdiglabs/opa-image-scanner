package admissionserver

import (
	"fmt"

	"k8s.io/api/admission/v1beta1"
	"k8s.io/klog"

	"image-scan-webhook/pkg/opaimagescanner"
	"strings"

	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Evaluate(admissionSpec *v1beta1.AdmissionRequest, e opaimagescanner.AdmissionEvaluator) (*v1beta1.AdmissionResponse, map[string]string, *corev1.Pod) {

	if err := validatePod(admissionSpec); err != nil {
		klog.Errorf("[admission-server] %v", err)
		return toAdmissionResponse(admissionSpec.UID, err), nil, nil
	} else {

		podName := admissionSpec.Name
		if podName == "" {
			podName = "<Not yet generated>"
		}
		klog.Infof("[admission-server] Admission review %s - evaluating admission of pod '%s'", admissionSpec.UID, podName)

		allowed, digestMappings, pod, denyReasons := e.Evaluate(admissionSpec)

		if pod != nil {
			if pod.Name != "" {
				podName = pod.Name
			} else if pod.GetObjectMeta().GetGenerateName() != "" {
				podName = pod.GetObjectMeta().GetGenerateName() + "*"
			}
		}

		klog.Infof("[admission-server] Admission review %s - finished evaluating admission of pod '%s'", admissionSpec.UID, podName)

		if allowed {
			klog.Infof("[admission-server] Admission review %s - pod '%s' accepted", admissionSpec.UID, podName)
			return &v1beta1.AdmissionResponse{UID: admissionSpec.UID, Allowed: true}, digestMappings, pod
		} else {
			reasons := strings.Join(denyReasons, "\n")

			klog.Infof("[admission-server] Admission review %s - pod '%s' rejected. Reasons:\n%s", admissionSpec.UID, podName, reasons)

			//TODO: More info? Annotations?
			reviewResponse := v1beta1.AdmissionResponse{}
			reviewResponse.UID = admissionSpec.UID
			reviewResponse.Allowed = false
			reviewResponse.Result = &metav1.Status{Message: reasons}
			return &reviewResponse, digestMappings, pod
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
