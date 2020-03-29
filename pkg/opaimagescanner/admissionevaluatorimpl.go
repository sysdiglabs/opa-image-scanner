package opaimagescanner

import (
	"fmt"
	"image-scan-webhook/pkg/imagescanner"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog"
)

//Implementation of AdmissionEvaluator interface
func (e *opaImageScannerEvaluator) Evaluate(a *v1beta1.AdmissionRequest) (accepted bool, digestMappings map[string]string, pod *corev1.Pod, errors []string) {

	accepted = true
	regoRules, err := e.getOPARulesFunc()
	if err != nil {
		regoRules = regoDefaultRules
	}

	if a == nil {
		return false, nil, nil, []string{"Admission request is <nil>"}
	}

	pod, err = getPod(a)
	if err != nil {
		return false, nil, nil, []string{err.Error()}
	}

	digestMappings = make(map[string]string)
	//TODO: Run in parallel and combine multiple containers output
	for _, container := range pod.Spec.Containers {

		klog.V(3).Infof("Checking container '%s' image '%s'", container.Name, container.Image)

		containerAccepted, digest, containerErrors := e.evaluateContainer(a, pod, &container, regoRules)
		if !containerAccepted {
			accepted = false
			errors = append(errors, containerErrors...)
		}

		digestMappings[container.Image] = digest
	}

	return

}
func (e *opaImageScannerEvaluator) evaluateContainer(a *v1beta1.AdmissionRequest, pod *v1.Pod, container *v1.Container, regoRules string) (accepted bool, digest string, errors []string) {

	var report *imagescanner.ScanReport

	digest, err := e.scanner.StartScan(container.Image)
	if err != nil {
		// TODO: Different if image not found, or cannot be started by other reasons (i.e. auth failed)
		klog.Warningf("start scan error: %v", err)
		report = &imagescanner.ScanReport{
			Status:      imagescanner.StatusScanFailed,
			ImageAndTag: container.Image,
		}
	} else if report, err = e.scanner.GetReport(container.Image, digest); err != nil {
		klog.Warningf("get scan report error: %v", err)
		report = &imagescanner.ScanReport{
			Status:      imagescanner.StatusReportNotAvailable,
			ImageAndTag: container.Image,
		}
	}

	opaInput := OPAInput{
		ScanReport:       report,
		AdmissionRequest: a,
		PodObject:        pod,
		ContainerObject:  container,
	}

	if err := e.opaEvaluator.Evaluate(regoQuery, regoRules, opaInput); err != nil {
		return false, "", []string{fmt.Sprintf("image '%s' for container '%s' failed policy check\nError: %v", container.Image, container.Name, err)}
	}

	return true, digest, nil

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
