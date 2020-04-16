package opa

type opaEvaluator struct {
}

// Verify that OPAImageScannerEvaluator implements opa.OPAEvaluator.
var _ OPAEvaluator = (*opaEvaluator)(nil)
