package opaimagescanner

import (
	"fmt"
	"image-scan-webhook/pkg/imagescanner"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"
)

//Implementation of ImageScannerAdmissionEvaluator interface
func (e *opaImageScannerEvaluator) ScanAndEvaluate(a *v1beta1.AdmissionRequest, pod *corev1.Pod) (accepted bool, digestMappings map[string]string, errors []string) {

	accepted = true
	regoRules, err := e.getOPARulesFunc()
	if err != nil {
		regoRules = regoDefaultRules
	}

	data, err := e.getOPADataFunc()
	if err != nil {
		return false, nil, []string{err.Error()}
	}

	if a == nil {
		return false, nil, []string{"Admission request is <nil>"}
	}

	if pod == nil {
		return false, nil, []string{"Pod data is <nil>"}
	}

	digestMappings = make(map[string]string)
	//TODO: Run in parallel and combine multiple containers output
	for _, container := range pod.Spec.Containers {

		klog.Infof("Checking container '%s' image '%s'", container.Name, container.Image)

		containerAccepted, digest, containerErrors := e.evaluateContainer(a, pod, &container, regoRules, data)
		digestMappings[container.Image] = digest
		if !containerAccepted {
			accepted = false
			errors = append(errors, containerErrors...)
		}
	}

	return

}

func (e *opaImageScannerEvaluator) evaluateContainer(a *v1beta1.AdmissionRequest, pod *corev1.Pod, container *corev1.Container, regoRules, data string) (accepted bool, digest string, errors []string) {

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

	if err := e.opaEvaluator.Evaluate(regoQuery, regoRules, data, opaInput); err != nil {
		return false, digest, []string{fmt.Sprintf("image '%s' for container '%s' failed policy check\nError: %v", container.Image, container.Name, err)}
	}

	return true, digest, nil

}
