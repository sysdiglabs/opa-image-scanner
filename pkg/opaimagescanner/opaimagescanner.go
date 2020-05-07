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

type GetStringDataFunction func() (string, error)

func NewImageScannerEvaluator(
	scanner imagescanner.Scanner,
	opaEvaluator opa.OPAEvaluator,
	getOPARulesFunc GetStringDataFunction,
	getOPAPreScanFulesFunc GetStringDataFunction,
	getOPADataFunc GetStringDataFunction,
) *opaImageScannerEvaluator {
	return &opaImageScannerEvaluator{
		scanner:                scanner,
		opaEvaluator:           opaEvaluator,
		getOPARulesFunc:        getOPARulesFunc,
		getOPAPreScanRulesFunc: getOPAPreScanFulesFunc,
		getOPADataFunc:         getOPADataFunc,
	}
}
