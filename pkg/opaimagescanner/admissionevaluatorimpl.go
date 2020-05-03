package opaimagescanner

import (
	"encoding/json"
	"fmt"
	"image-scan-webhook/pkg/imagescanner"
	"image-scan-webhook/pkg/opa"
	"strings"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"
)

//Implementation of ImageScannerAdmissionEvaluator interface
func (e *opaImageScannerEvaluator) ScanAndEvaluate(a *v1beta1.AdmissionRequest, pod *corev1.Pod) (accepted bool, digestMappings map[string]string, errors []string) {

	if a == nil {
		return false, nil, []string{"Admission request is <nil>"}
	}

	if pod == nil {
		return false, nil, []string{"Pod data is <nil>"}
	}

	regoRules, err := e.getOPARulesFunc()
	if err != nil {
		regoRules = regoDefaultRules
	}

	preScanRegoRules, err := e.getOPAPreScanRulesFunc()
	if err != nil {
		preScanRegoRules = regoDefaultPreScanRules
	}

	data, err := e.getOPADataFunc()
	if err != nil {
		return false, nil, []string{err.Error()}
	}

	klog.Infof("Pre-scan check for admission review %s", a.UID)
	accepted, rejected, message := e.preScanEvaluate(a, pod, preScanRegoRules, data)

	if accepted {
		klog.Infof("Pre-scan check ALLOWED pod for admission review %s", a.UID)
		return
	}

	if rejected {
		klog.Infof("Pre-scan check REJECTED pod for admission review %s\nReason: %s", a.UID, message)
		accepted = false
		errors = []string{fmt.Sprintf("Pre-scan rejected. Reasons: %s", message)}
		return
	}

	klog.Infof("Pre-scan check admission review %s finished. Not conclusive, proceeding to scan.", a.UID)

	accepted = true
	digestMappings = make(map[string]string)

	//TODO: Run in parallel and combine multiple containers output
	for _, container := range pod.Spec.Containers {
		klog.Infof("Scan check for admission review %s container '%s' image '%s'", a.UID, container.Name, container.Image)

		containerAccepted, digest, message := e.evaluateContainer(a, pod, &container, regoRules, data)
		digestMappings[container.Image] = digest
		if containerAccepted {
			klog.Infof("Scan check for admission review %s ALLOWED container '%s' image '%s'", a.UID, container.Name, container.Image)
		} else {
			klog.Infof("Scan check for admission review %s REJECTED container '%s' image '%s' \nReason: %s", a.UID, container.Name, container.Image, message)
			accepted = false
			errors = append(errors, fmt.Sprintf("Image '%s' for container '%s' failed scan policy check: %s", container.Image, container.Name, message))
		}
	}

	return
}

func (e *opaImageScannerEvaluator) preScanEvaluate(a *v1beta1.AdmissionRequest, pod *corev1.Pod, preScanRegoRules, data string) (accepted, rejected bool, message string) {
	opaInput := OPAInput{
		ScanReport:       nil,
		AdmissionRequest: a,
		PodObject:        pod,
		ContainerObject:  nil,
	}

	//TODO: include msg in pre_allow_image?
	if res, err := e.opaEvaluator.Evaluate(regoPreScanAllowQuery, preScanRegoRules, data, opaInput); err != nil {
		return false, true, err.Error()
	} else if len(res) > 0 {
		return true, false, ""
	}

	res, err := e.opaEvaluator.Evaluate(regoPreScanRejectQuery, preScanRegoRules, data, opaInput)
	denyReasons := expressions2StringList(res, err)

	if denyReasons != nil {
		return false, true, strings.Join(denyReasons, ", ")
	}

	return false, false, ""
}

func (e *opaImageScannerEvaluator) evaluateContainer(a *v1beta1.AdmissionRequest, pod *corev1.Pod, container *corev1.Container, regoRules, data string) (accepted bool, digest string, message string) {

	var report *imagescanner.ScanReport
	var err error

	if digest, err = e.scanner.StartScan(container.Image); err != nil {
		// TODO: Different if image not found, or cannot be started by other reasons (i.e. auth failed)
		klog.Warningf("start scan error: %v", err)
		report = &imagescanner.ScanReport{
			Status:      imagescanner.StatusScanFailed,
			ImageAndTag: container.Image,
		}
	} else if scanPolicyId, err := getContainerPolicy(a, pod, container, data); err != nil {
		klog.Warningf("retrieve scanPolicyId error: %v", err)
		report = &imagescanner.ScanReport{
			Status:      imagescanner.StatusScanFailed,
			ImageAndTag: container.Image,
		}
	} else if report, err = e.scanner.GetReport(container.Image, digest, scanPolicyId); err != nil {
		klog.Warningf("get scan report error: %v", err)
		report = &imagescanner.ScanReport{
			Status:      imagescanner.StatusReportNotAvailable,
			ImageAndTag: container.Image,
		}
	}

	opaInput := OPAInput{
		ScanReport:       report,
		AdmissionRequest: a,
		PodObject:        pod,
		ContainerObject:  container,
	}

	//TODO: Pass data as interface{}
	res, err := e.opaEvaluator.Evaluate(regoQuery, regoRules, data, opaInput)
	denyReasons := expressions2StringList(res, err)

	if denyReasons != nil {
		return false, digest, strings.Join(denyReasons, ", ")
	}

	return true, digest, ""

}

func expressions2StringList(res []opa.EvaluationResult, err error) []string {
	if err != nil {
		return []string{fmt.Sprintf("Evaluation error: %s", err)}
	} else if len(res) != 1 || len(res[0]) != 1 {
		return []string{fmt.Sprintf("Evaluation error - unexpected result length: %s", res)}
	} else {
		if expressionList, ok := res[0][0].Value.([]interface{}); !ok {
			return []string{fmt.Sprintf("Evaluation error - unexpected expression type: %T - value: %s", res[0][0].Value, res[0][0].Value)}
		} else if len(expressionList) == 0 {
			return nil
		} else {

			denyReasons := make([]string, len(expressionList))
			for i := range expressionList {
				var ok bool
				denyReasons[i], ok = expressionList[i].(string)
				if !ok {
					return []string{fmt.Sprintf("Evaluation error - unexpected value type: %T - value: %s", expressionList[i], expressionList[i])}
				}
			}

			return denyReasons
		}
	}
}

func getContainerPolicy(a *v1beta1.AdmissionRequest, pod *corev1.Pod, container *corev1.Container, data string) (string, error) {
	parsedData, err := parseData(data)
	if err != nil {
		return "", err
	}

	//TODO: Get policy from namespace
	policies, ok := parsedData["policies"].(map[string]interface{})
	if ok {
		scanPolicyId, ok := policies["scanPolicyId"].(string)
		if ok {
			return scanPolicyId, nil
		}
	}

	return "", nil
}

func parseData(data string) (map[string]interface{}, error) {
	klog.V(3).Infof("[rego] Data is:\n%s", data)
	var jsonData map[string]interface{}

	err := json.Unmarshal([]byte(data), &jsonData)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}
