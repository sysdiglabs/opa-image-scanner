package admissionserver

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"k8s.io/api/admission/v1beta1"
)

func TestEvaluateAccepted(t *testing.T) {
	review := &v1beta1.AdmissionRequest{}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Error(err)
	} else {
		json.Unmarshal(b, review)
	}

	evaluator := mockImageScannerEvaluator{Accepted: true}
	response, digestMappings, _ := Evaluate(review, nil, &evaluator)

	if !response.Allowed {
		t.Fatalf("Admission should not be allowed")
	}

	if response.UID != review.UID {
		t.Fatalf("Unexpected UID: %s", response.UID)
	}

	if response.Result != nil {
		t.Fatalf("Response Result should be nil")
	}

	if digestMappings["image1:tag1"] != "digest1" {
		t.Fatalf("Unexpected mapping: %s", digestMappings["image1:tag1"])
	}

	if digestMappings["image2:tag2"] != "digest2" {
		t.Fatalf("Unexpected mapping: %s", digestMappings["image2:tag2"])
	}
}

func TestEvaluateRejected(t *testing.T) {
	review := &v1beta1.AdmissionRequest{}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Error(err)
	} else {
		json.Unmarshal(b, review)
	}

	evaluator := mockImageScannerEvaluator{Accepted: false}
	response, digestMappings, _ := Evaluate(review, nil, &evaluator)

	if response.Allowed {
		t.Fatalf("Admission should not be allowed")
	}

	if response.UID != review.UID {
		t.Fatalf("Unexpected UID: %s", response.UID)
	}

	if response.Result.Message != "error1\nerror2" {
		t.Fatalf("Unexpected Message: %s", response.Result.Message)
	}

	if digestMappings["image1:tag1"] != "digest1" {
		t.Fatalf("Unexpected mapping: %s", digestMappings["image1:tag1"])
	}

	if digestMappings["image2:tag2"] != "digest2" {
		t.Fatalf("Unexpected mapping: %s", digestMappings["image2:tag2"])
	}
}

func TestEvaluateRejectedNilPod(t *testing.T) {
	review := &v1beta1.AdmissionRequest{}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Error(err)
	} else {
		json.Unmarshal(b, review)
	}

	evaluator := mockImageScannerEvaluator{Accepted: false, AllNull: true}
	response, _, _ := Evaluate(review, nil, &evaluator)

	if response.Allowed {
		t.Fatalf("Admission should not be allowed")
	}

	if response.UID != review.UID {
		t.Fatalf("Unexpected UID: %s", response.UID)
	}

	if response.Result.Message != "error1\nerror2" {
		t.Fatalf("Unexpected Message: %s", response.Result.Message)
	}

}

func TestEvaluatePreScanAccepted(t *testing.T) {
	review := &v1beta1.AdmissionRequest{}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Error(err)
	} else {
		json.Unmarshal(b, review)
	}

	preEvaluator := mockPreScanEvaluator{Accept: true}
	evaluator := mockImageScannerEvaluator{Accepted: false}
	response, _, _ := Evaluate(review, &preEvaluator, &evaluator)

	if evaluator.ScanAndEvaluateCalled {
		t.Fatalf("ScanAndEvaluate should not be called")
	}

	if !response.Allowed {
		t.Fatalf("Admission should not be rejected")
	}

	if response.UID != review.UID {
		t.Fatalf("Unexpected UID: %s", response.UID)
	}

}

func TestEvaluatePreScanRejected(t *testing.T) {
	review := &v1beta1.AdmissionRequest{}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Error(err)
	} else {
		json.Unmarshal(b, review)
	}

	preEvaluator := mockPreScanEvaluator{Reject: true}
	evaluator := mockImageScannerEvaluator{Accepted: true}
	response, _, _ := Evaluate(review, &preEvaluator, &evaluator)

	if evaluator.ScanAndEvaluateCalled {
		t.Fatalf("ScanAndEvaluate should not be called")
	}

	if response.Allowed {
		t.Fatalf("Admission should not be allowed")
	}

	if response.UID != review.UID {
		t.Fatalf("Unexpected UID: %s", response.UID)
	}

	if response.Result.Message != "pre-error-1\npre-error-2" {
		t.Fatalf("Unexpected Message: %s", response.Result.Message)
	}

}

func TestEvaluatePreScanIndecisive(t *testing.T) {
	review := &v1beta1.AdmissionRequest{}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Error(err)
	} else {
		json.Unmarshal(b, review)
	}

	preEvaluator := mockPreScanEvaluator{}
	evaluator := mockImageScannerEvaluator{Accepted: true}
	response, digestMappings, _ := Evaluate(review, &preEvaluator, &evaluator)

	if !evaluator.ScanAndEvaluateCalled {
		t.Fatalf("ScanAndEvaluate should be called")
	}

	if !response.Allowed {
		t.Fatalf("Admission should not be allowed")
	}

	if response.UID != review.UID {
		t.Fatalf("Unexpected UID: %s", response.UID)
	}

	if response.Result != nil {
		t.Fatalf("Response Result should be nil")
	}

	if digestMappings["image1:tag1"] != "digest1" {
		t.Fatalf("Unexpected mapping: %s", digestMappings["image1:tag1"])
	}

	if digestMappings["image2:tag2"] != "digest2" {
		t.Fatalf("Unexpected mapping: %s", digestMappings["image2:tag2"])
	}
}
