package admissionserver

import (
	"image-scan-webhook/pkg/opaimagescanner"

	genericadmissionserver "github.com/openshift/generic-admission-server/pkg/cmd"
)

func Run(e opaimagescanner.AdmissionEvaluator) {
	genericadmissionserver.RunAdmissionServer(
		//	&admissionHook{evaluator: e},
		&mutationHook{evaluator: e},
	)
}
