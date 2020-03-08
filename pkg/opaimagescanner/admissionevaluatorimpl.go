package opaimagescanner

import (
	"fmt"
	"image-scan-webhook/pkg/admissionserver"
	"io/ioutil"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog"
)

const regoFileDefault string = `
package imageadmission

deny_image[msg] {
	msg := "No rules defined. Please define 'imageadmission' package with deny_image[msg] rules"
}
`

func readOpaRules(rulesFiles string) string {
	regoFileContents, err := ioutil.ReadFile(rulesFiles)
	if err != nil {
		return regoFileDefault
	} else {
		return string(regoFileContents)
	}
}

func (e *opaImageScannerEvaluator) evaluateContainer(container *v1.Container, regoRules string, c *admissionserver.AdmissionEvaluationContext) (accepted bool, errors []string) {

	digest, err := e.scanner.StartScan(container.Image)
	if err != nil {
		// TODO: Evaluate the error with OPA
		klog.Warningf("start scan error: %v", err)
		return true, nil
	}

	report, err := e.scanner.GetReport(container.Image, digest)
	if err != nil {
		// TODO: Evaluate the error with OPA
		klog.Warningf("get scan report error: %v", err)
		return true, nil

	}

	opaInput := OPAInput{report, c.AdmissionRequest}

	if err := e.evaluateFunc(regoRules, opaInput); err != nil {
		return false, []string{fmt.Sprintf("image '%s' for container '%s' failed policy check\nError: %v", container.Image, container.Name, err)}
	}

	return true, nil

}

//Implementation of admissionserver.admissionEvaluator interface
func (e *opaImageScannerEvaluator) Evaluate(c *admissionserver.AdmissionEvaluationContext) (accepted bool, errors []string) {

	accepted = true
	regoRules := readOpaRules(e.rulesFile)

	//TODO: Run in parallel and combine multiple containers output
	for _, container := range c.PodObject.Spec.Containers {

		klog.Infof("Checking container '%s' image '%s'", container.Name, container.Image)

		if containerAccepted, containerErrors := e.evaluateContainer(&container, regoRules, c); !containerAccepted {
			accepted = false
			errors = append(errors, containerErrors...)
		}

	}

	return accepted, errors

}
