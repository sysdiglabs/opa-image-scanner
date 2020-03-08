package opa

import (
	"encoding/json"
	"image-scan-webhook/pkg/imagescanner"
	"image-scan-webhook/pkg/opaimagescanner"
	"io/ioutil"
	"strings"
	"testing"

	"k8s.io/api/admission/v1beta1"
)

func TestDummyDontDeny(t *testing.T) {
	rules := `
	package imageadmission
	deny_image[msg] {
		1=0
		msg := "Should not happen"
	}
	`

	err := Evaluate(rules, "testInput")
	if err != nil {
		t.Errorf("Failed: %v", err)
	}
}

func TestDummyDeny(t *testing.T) {
	rules := `
	package imageadmission
	deny_image[msg] {
		msg := "Image denied"
	}
	`

	err := Evaluate(rules, "testInput")
	if !strings.HasPrefix(err.Error(), "Image denied by OPA rules") {
		t.Errorf("Failed. Missing 'Image denied by OPA rules' reason: %v", err)
	}
}

func TestEvaluateScanResultPassed(t *testing.T) {
	input := opaimagescanner.OPAInput{
		ScanReport: &imagescanner.ScanReport{Passed: true},
	}

	rules := `
	package imageadmission

	allow_image {
			input.ScanReport.Passed == true
	}

	deny_image[msg] {
			not allow_image
			msg := "Denying images by default"
	}
	`

	err := Evaluate(rules, input)
	if err != nil {
		t.Errorf("Failed: %v", err)
	}
}

func TestEvaluateScanResultFailed(t *testing.T) {
	input := opaimagescanner.OPAInput{
		ScanReport: &imagescanner.ScanReport{Passed: false},
	}

	rules := `
	package imageadmission

	allow_image {
			input.ScanReport.Passed == true
	}

	deny_image[msg] {
			not allow_image
			msg := "Denying images by default"
	}
	`

	err := Evaluate(rules, input)
	if !strings.HasPrefix(err.Error(), "Image denied by OPA rules") {
		t.Errorf("Failed. Missing 'Image denied by OPA rules' reason: %v", err)
	}
}

func TestEvaluateAdmissionReviewAllowByNamespace(t *testing.T) {
	input := opaimagescanner.OPAInput{}
	input.AdmissionRequest = &v1beta1.AdmissionRequest{}
	input.ScanReport = &imagescanner.ScanReport{Passed: false}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Error(err)
	} else {
		json.Unmarshal(b, input.AdmissionRequest)
	}

	rules := `
	package imageadmission

	allow_image {
		input.AdmissionRequest.object.metadata.namespace == "test-ns"
	}

	allow_image {
		input.ScanReport.Passed == true
	}

	deny_image[msg] {
		not allow_image
		msg := "Denying images by default"
	}
	`

	err := Evaluate(rules, input)
	if err != nil {
		t.Errorf("Failed: %v", err)
	}
}

func TestEvaluateAdmissionReviewDenyByNamespace(t *testing.T) {
	input := opaimagescanner.OPAInput{}
	input.AdmissionRequest = &v1beta1.AdmissionRequest{}
	input.ScanReport = &imagescanner.ScanReport{Passed: true}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Error(err)
	} else {
		json.Unmarshal(b, input.AdmissionRequest)
	}

	rules := `
	package imageadmission


	allow_image {
		input.ScanReport.Passed == true
	}

	deny_image[msg] {
		input.AdmissionRequest.object.metadata.namespace == "test-ns"
		msg := "Not allowed in this namespace"
	}
	
	deny_image[msg] {
		not allow_image
		msg := "Denying images by default"
	}
	`

	err := Evaluate(rules, input)
	if !strings.Contains(err.Error(), "Not allowed in this namespace") {
		t.Errorf("Failed. Missing 'Not allowed in this namespace' reason: %v", err)
	}
}
