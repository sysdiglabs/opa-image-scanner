package admissionserver

import (
	"image-scan-webhook/pkg/imagescanner"

	genericadmissionserver "github.com/openshift/generic-admission-server/pkg/cmd"
)

func Run(preScanEvaluator imagescanner.PreScanAdmissionEvaluator, imageScannerEvaluator imagescanner.ImageScannerAdmissionEvaluator) {
	genericadmissionserver.RunAdmissionServer(
		&mutationHook{
			preScanEvaluator:      preScanEvaluator,
			imageScannerEvaluator: imageScannerEvaluator},
	)
}
