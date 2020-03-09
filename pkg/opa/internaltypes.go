package opa

type opaEvaluator struct {
}

// Verify that OPAImageScannerEvaluator implements admissionserver.AdmissionEvaluator.
var _ OPAEvaluator = (*opaEvaluator)(nil)
