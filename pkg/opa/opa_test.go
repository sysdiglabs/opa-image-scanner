package opa

import (
	"encoding/json"
	"image-scan-webhook/pkg/imagescanner"
	"io/ioutil"
	"strings"
	"testing"

	"k8s.io/api/admission/v1beta1"
)

const regoQuery string = "data.imageadmission.deny_image"

type OPAInput struct {
	ScanReport       *imagescanner.ScanReport
	AdmissionRequest *v1beta1.AdmissionRequest
}

func TestDummyDontDeny(t *testing.T) {
	rules := `
	package imageadmission
	deny_image[msg] {
		1=0
		msg := "Should not happen"
	}
	`

	err := NewEvaluator().Evaluate(regoQuery, rules, "{}", "testInput")
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
}

func TestDummyDeny(t *testing.T) {
	rules := `
	package imageadmission
	deny_image[msg] {
		msg := "Image denied"
	}
	`

	err := NewEvaluator().Evaluate(regoQuery, rules, "{}", "testInput")
	if err == nil || !strings.HasPrefix(err.Error(), "Image denied by OPA rules:\n- Image denied") {
		t.Fatalf("Failed. Missing 'Image denied by OPA rules' reason:\n%v", err)
	}
}

func TestEvaluateData(t *testing.T) {
	rules := `
	package imageadmission

	deny_image[msg] {
		msg := data.deny_msg
	}

	`

	data := `
	{ "deny_msg" : "Deny msg from data" }
	`

	err := NewEvaluator().Evaluate(regoQuery, rules, data, "")

	if err == nil || !strings.HasPrefix(err.Error(), "Image denied by OPA rules:\n- Deny msg from data") {
		t.Fatalf("Failed. Missing 'Image denied by OPA rules' reason: %v", err)
	}

}

func TestEvaluateScanResultPassed(t *testing.T) {
	input := OPAInput{
		ScanReport: &imagescanner.ScanReport{Status: "accepted"},
	}

	rules := `
	package imageadmission

	allow_image {
		input.ScanReport.Status == "accepted"
	}

	deny_image[msg] {
		not allow_image
		msg := "Denying images by default"
	}
	`

	err := NewEvaluator().Evaluate(regoQuery, rules, "{}", input)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
}

func TestEvaluateScanResultFailed(t *testing.T) {
	input := OPAInput{
		ScanReport: &imagescanner.ScanReport{Status: "rejected"},
	}

	rules := `
	package imageadmission

	allow_image {
		input.ScanReport.Status == "accepted"
	}

	deny_image[msg] {
		not allow_image
		msg := "Denying images by default"
	}
	`

	err := NewEvaluator().Evaluate(regoQuery, rules, "{}", input)
	if err == nil || !strings.HasPrefix(err.Error(), "Image denied by OPA rules") {
		t.Fatalf("Failed. Missing 'Image denied by OPA rules' reason: %v", err)
	}
}

func TestEvaluateAdmissionReviewAllowByNamespace(t *testing.T) {
	input := OPAInput{}
	input.AdmissionRequest = &v1beta1.AdmissionRequest{}
	input.ScanReport = &imagescanner.ScanReport{Status: "rejected"}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Fatal(err)
	} else {
		json.Unmarshal(b, input.AdmissionRequest)
	}

	rules := `
	package imageadmission

	allow_image {
		input.AdmissionRequest.object.metadata.namespace == "test-ns"
	}

	allow_image {
		input.ScanReport.Status == "accepted"
	}

	deny_image[msg] {
		not allow_image
		msg := "Denying images by default"
	}
	`

	err := NewEvaluator().Evaluate(regoQuery, rules, "{}", input)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}
}

func TestEvaluateAdmissionReviewDenyByNamespace(t *testing.T) {
	input := OPAInput{}
	input.AdmissionRequest = &v1beta1.AdmissionRequest{}
	input.ScanReport = &imagescanner.ScanReport{Status: "accepted"}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Fatal(err)
	} else {
		json.Unmarshal(b, input.AdmissionRequest)
	}

	rules := `
	package imageadmission


	allow_image {
		input.ScanReport.Status == "accepted"
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

	err := NewEvaluator().Evaluate(regoQuery, rules, "{}", input)
	if err == nil || !strings.Contains(err.Error(), "Not allowed in this namespace") {
		t.Fatalf("Failed. Missing 'Not allowed in this namespace' reason: %v", err)
	}
}

func TestEvaluateAdmissionReviewAllowByPrefix(t *testing.T) {
	input := OPAInput{}
	input.AdmissionRequest = &v1beta1.AdmissionRequest{}
	input.ScanReport = &imagescanner.ScanReport{
		Status:      "rejected",
		ImageAndTag: "mysaferegistry.io/container-image:1.01",
	}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Fatal(err)
	} else {
		json.Unmarshal(b, input.AdmissionRequest)
	}

	rules := `
	package imageadmission

	allowedRegistry := "mysaferegistry.io/"

	allow_image {
		input.ScanReport.Status == "accepted"
	}

	allow_image {
		startswith(input.ScanReport.ImageAndTag, allowedRegistry)
	}
	
	deny_image[msg] {
		not allow_image
		msg := "Denying images by default"
	}
	`

	err := NewEvaluator().Evaluate(regoQuery, rules, "{}", input)
	if err != nil {
		t.Errorf("Failed: %v", err)
	}
}

func TestEvaluateAdmissionReviewDenyByPrefix(t *testing.T) {
	input := OPAInput{}
	input.AdmissionRequest = &v1beta1.AdmissionRequest{}
	input.ScanReport = &imagescanner.ScanReport{
		Status:      "accepted",
		ImageAndTag: "badregistry.io/container-image:1.01",
	}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Fatal(err)
	} else {
		json.Unmarshal(b, input.AdmissionRequest)
	}

	rules := `
	package imageadmission

	deniedRegistry := "badregistry.io/"

	allow_image {
		input.ScanReport.Status == "accepted"
	}

	deny_image[msg] {
		startswith(input.ScanReport.ImageAndTag, deniedRegistry)
		msg := "Deny blacklisted registry"
	}
	
	deny_image[msg] {
		not allow_image
		msg := "Denying images by default"
	}
	`

	err := NewEvaluator().Evaluate(regoQuery, rules, "{}", input)
	if err == nil || !strings.Contains(err.Error(), "Deny blacklisted registry") {
		t.Errorf("Failed. Missing 'Deny blacklisted registry' reason: %v", err)
	}
}
