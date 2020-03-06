package admissionserver

import genericadmissionserver "github.com/openshift/generic-admission-server/pkg/cmd"

func Run(e AdmissionEvaluator) {
	genericadmissionserver.RunAdmissionServer(
		&admissionHook{evaluator: e},
	)
}
