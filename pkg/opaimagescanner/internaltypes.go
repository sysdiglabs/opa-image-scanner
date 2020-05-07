package opaimagescanner

import (
	"image-scan-webhook/pkg/imagescanner"
	"image-scan-webhook/pkg/opa"
)

const regoQuery string = "data.imageadmission.deny_image"

const regoPreScanAllowQuery string = "data.imageadmission.allow_pod"
const regoPreScanRejectQuery string = "data.imageadmission.deny_pod"

const regoDefaultRules string = `
package imageadmission

deny_image[msg] {
	msg := "No rules defined. Please define 'imageadmission' package with deny_image[msg] rules"
}
`

const regoDefaultPreScanRules string = `
package imageadmission

deny_pod[msg] {
	msg := "No pre-scan rules defined. Please define 'imageadmission' package with deny_pod[msg] rules"
}
`

type opaImageScannerEvaluator struct {
	scanner                imagescanner.Scanner
	opaEvaluator           opa.OPAEvaluator
	getOPARulesFunc        GetStringDataFunction
	getOPAPreScanRulesFunc GetStringDataFunction
	getOPADataFunc         GetStringDataFunction
}

// Verify that opaImageScannerEvaluator implements ImageScannerAdmissionEvaluator.
var _ imagescanner.ImageScannerAdmissionEvaluator = (*opaImageScannerEvaluator)(nil)
