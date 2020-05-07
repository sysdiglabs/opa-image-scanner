package admissionserver

import (
	"image-scan-webhook/pkg/imagescanner"

	genericadmissionserver "github.com/openshift/generic-admission-server/pkg/cmd"
)

func Run(imageScannerEvaluator imagescanner.ImageScannerAdmissionEvaluator) {
	genericadmissionserver.RunAdmissionServer(
		&mutationHook{
			imageScannerEvaluator: imageScannerEvaluator},
	)
}
