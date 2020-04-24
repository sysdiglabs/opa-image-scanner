package opa

import (
	"encoding/json"
	"image-scan-webhook/pkg/imagescanner"
	"io/ioutil"
	"testing"

	"k8s.io/api/admission/v1beta1"
)

const regoQuery string = "data.imageadmission.deny_image"

type OPAInput struct {
	ScanReport       *imagescanner.ScanReport
	AdmissionRequest *v1beta1.AdmissionRequest
}

func expectNoMessages(t *testing.T, res []EvaluationResult, err error) {
	if err != nil {
		t.Fatal(err)
	}

	if len(res) != 1 {
		t.Fatalf("More results than expeced: %d", len(res))
	}

	if len(res[0]) != 1 {
		t.Fatalf("More expressions than expected: %d", len(res))
	}

	if _, ok := res[0][0].Value.([]interface{}); !ok {
		t.Fatalf("Unexpected expression type: %T", res[0][0].Value)
	}

	if v := res[0][0].Value.([]interface{}); len(v) > 0 {
		t.Fatalf("Unexpected value: %s", v)
	}
}

func expectMessage(t *testing.T, res []EvaluationResult, err error, expectedMessage string) {
	if err != nil {
		t.Fatal(err)
	}

	if len(res) != 1 {
		t.Fatalf("More results than expeced: %d", len(res))
	}

	if len(res[0]) != 1 {
		t.Fatalf("More expressions than expected: %d", len(res))
	}

	if _, ok := res[0][0].Value.([]interface{}); !ok {
		t.Fatalf("Unexpected expression type: %T", res[0][0].Value)
	}

	if v := res[0][0].Value.([]interface{})[0].(string); v != expectedMessage {
		t.Fatalf("Unexpected value: %s", v)
	}
}

func TestDummyDontDeny(t *testing.T) {
	rules := `
	package imageadmission
	deny_image[msg] {
		1=0
		msg := "Should not happen"
	}
	`

	res, err := NewEvaluator().Evaluate(regoQuery, rules, "{}", "testInput")
	expectNoMessages(t, res, err)

}

func TestDummyDeny(t *testing.T) {
	rules := `
	package imageadmission
	deny_image[msg] {
		msg := "Image denied"
	}
	`

	res, err := NewEvaluator().Evaluate(regoQuery, rules, "{}", "testInput")

	expectMessage(t, res, err, "Image denied")
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

	res, err := NewEvaluator().Evaluate(regoQuery, rules, data, "")

	expectMessage(t, res, err, "Deny msg from data")

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

	res, err := NewEvaluator().Evaluate(regoQuery, rules, "{}", input)
	expectNoMessages(t, res, err)
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

	res, err := NewEvaluator().Evaluate(regoQuery, rules, "{}", input)

	expectMessage(t, res, err, "Denying images by default")
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

	res, err := NewEvaluator().Evaluate(regoQuery, rules, "{}", input)

	expectNoMessages(t, res, err)
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

	res, err := NewEvaluator().Evaluate(regoQuery, rules, "{}", input)
	expectMessage(t, res, err, "Not allowed in this namespace")
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

	res, err := NewEvaluator().Evaluate(regoQuery, rules, "{}", input)
	expectNoMessages(t, res, err)

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

	res, err := NewEvaluator().Evaluate(regoQuery, rules, "{}", input)
	expectMessage(t, res, err, "Deny blacklisted registry")
}
