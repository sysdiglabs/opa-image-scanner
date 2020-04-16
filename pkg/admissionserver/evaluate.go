package admissionserver

import (
	"fmt"
	"image-scan-webhook/pkg/imagescanner"

	"k8s.io/api/admission/v1beta1"
	"k8s.io/klog"

	"strings"

	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Evaluate(admissionSpec *v1beta1.AdmissionRequest, e imagescanner.ImageScannerAdmissionEvaluator) (*v1beta1.AdmissionResponse, map[string]string, *corev1.Pod) {

	if err := validatePod(admissionSpec); err != nil {
		klog.Errorf("[admission-server] %v", err)
		return toAdmissionResponse(admissionSpec.UID, err), nil, nil
	} else {

		podName := admissionSpec.Name
		if podName == "" {
			podName = "<Not yet generated>"
		}

		pod, err := getPod(admissionSpec)
		if err != nil {
			klog.Errorf("[admission-server] %v", err)
			return toAdmissionResponse(admissionSpec.UID, err), nil, nil
		}

		if pod != nil {
			if pod.Name != "" {
				podName = pod.Name
			} else if pod.GetObjectMeta().GetGenerateName() != "" {
				podName = pod.GetObjectMeta().GetGenerateName() + "*"
			}
		}

		klog.Infof("[admission-server] Admission review %s - evaluating admission of pod '%s'", admissionSpec.UID, podName)

		// TODO: Pre-scan rules, and skip ImageScanner if directly accepted

		allowed, digestMappings, denyReasons := e.ScanAndEvaluate(admissionSpec, pod)

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

func getPod(a *v1beta1.AdmissionRequest) (*corev1.Pod, error) {

	raw := a.Object.Raw

	if raw == nil {
		return nil, fmt.Errorf("Pod data is <nil>")
	}

	pod := corev1.Pod{}
	deserializer := codecs.UniversalDeserializer()
	if _, schema, err := deserializer.Decode(raw, nil, &pod); err != nil {
		return nil, err
	} else if schema == nil {
		return nil, fmt.Errorf("Could not find a schema")
	}

	return &pod, nil
}
