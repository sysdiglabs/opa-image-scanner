package opaimagescanner

import (
	"image-scan-webhook/pkg/admissionserver"
	"image-scan-webhook/pkg/imagescanner"

	"k8s.io/api/admission/v1beta1"
)

type EvaluationFunction func(rules string, input interface{}) error

type opaImageScannerEvaluator struct {
	scanner      imagescanner.Scanner
	rulesFile    string
	evaluateFunc EvaluationFunction
}

func NewEvaluator(
	scanner imagescanner.Scanner,
	rulesFile string,
	evaluateFunc EvaluationFunction,
) *opaImageScannerEvaluator {
	return &opaImageScannerEvaluator{
		scanner:      scanner,
		rulesFile:    rulesFile,
		evaluateFunc: evaluateFunc,
	}
}

// Verify that OPAImageScannerEvaluator implements admissionserver.AdmissionEvaluator.
var _ admissionserver.AdmissionEvaluator = (*opaImageScannerEvaluator)(nil)

type OPAInput struct {
	ScanReport       *imagescanner.ScanReport
	AdmissionRequest *v1beta1.AdmissionRequest
}
