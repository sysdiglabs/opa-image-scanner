package opaimagescanner

import (
	"image-scan-webhook/pkg/imagescanner"
	"image-scan-webhook/pkg/opa"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

type OPAInput struct {
	ScanReport       *imagescanner.ScanReport
	AdmissionRequest *v1beta1.AdmissionRequest
	PodObject        *corev1.Pod
	ContainerObject  *corev1.Container
}

type AdmissionEvaluator interface {
	Evaluate(a *v1beta1.AdmissionRequest) (accepted bool, digestMappings map[string]string, pod *corev1.Pod, errors []string)
}

type GetOPARulesFunction func() (string, error)

func NewEvaluator(
	scanner imagescanner.Scanner,
	opaEvaluator opa.OPAEvaluator,
	getOPARulesFunc GetOPARulesFunction,
) *opaImageScannerEvaluator {
	return &opaImageScannerEvaluator{
		scanner:         scanner,
		opaEvaluator:    opaEvaluator,
		getOPARulesFunc: getOPARulesFunc,
	}
}
