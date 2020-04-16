package admissionserver

import (
	"encoding/json"
	"image-scan-webhook/pkg/imagescanner"
	"io/ioutil"
	"testing"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

type mockImageScannerEvaluator struct {
	Accepted bool
	AllNull  bool
}

func (m *mockImageScannerEvaluator) ScanAndEvaluate(a *v1beta1.AdmissionRequest, pod *corev1.Pod) (accepted bool, digestMappings map[string]string, errors []string) {
	accepted = m.Accepted
	errors = []string{"error1", "error2"}
	if !m.AllNull {
		digestMappings = map[string]string{"image1:tag1": "digest1", "image2:tag2": "digest2"}
	}
	return
}

// Verify that mockImageScannerEvaluator implements opaimagescanner.ImageScannerAdmissionEvaluator.
var _ imagescanner.ImageScannerAdmissionEvaluator = (*mockImageScannerEvaluator)(nil)

func TestMutationHookAdmit(t *testing.T) {
	hook := &mutationHook{evaluator: &mockImageScannerEvaluator{true, false}}

	review := &v1beta1.AdmissionRequest{}
	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Error(err)
	} else {
		json.Unmarshal(b, review)
	}

	response := hook.Admit(review)

	if !response.Allowed {
		t.Fatalf("Admission should not be allowed")
	}

	if response.UID != review.UID {
		t.Fatalf("Unexpected UID: %s", response.UID)
	}

	if response.Result != nil {
		t.Fatalf("Response Result should be nil")
	}

	if *response.PatchType != v1beta1.PatchType("JSONPatch") {
		t.Fatalf("Unexpected PatchType: %s", *response.PatchType)
	}

	var a []interface{}
	if err := json.Unmarshal(response.Patch, &a); err != nil {
		t.Fatalf("Unmarshal error for JSON Patch: %s\n%v", string(response.Patch), err)
	}

	if string(response.Patch) != `[{"op": "add", "path": "/metadata/annotations", "value": {}}, {"op": "replace", "path": "/spec/containers/0/image", "value": "image1@digest1"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-1-original-image", "value": "image1:tag1"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-1-mutated-image", "value": "image1@digest1"}, {"op": "replace", "path": "/spec/containers/1/image", "value": "image2@digest2"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-2-original-image", "value": "image2:tag2"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-2-mutated-image", "value": "image2@digest2"}]` {
		t.Fatalf("Unexpected JSON Patch: %s", string(response.Patch))
	}
}

func TestMutationHookPreserveAnnotations(t *testing.T) {
	hook := &mutationHook{evaluator: &mockImageScannerEvaluator{true, false}}

	review := &v1beta1.AdmissionRequest{}
	if b, err := ioutil.ReadFile("./assets/admission-review-with-annotations.json"); err != nil {
		t.Error(err)
	} else {
		json.Unmarshal(b, review)
	}

	response := hook.Admit(review)

	if !response.Allowed {
		t.Fatalf("Admission should not be allowed")
	}

	if response.UID != review.UID {
		t.Fatalf("Unexpected UID: %s", response.UID)
	}

	if response.Result != nil {
		t.Fatalf("Response Result should be nil")
	}

	if *response.PatchType != v1beta1.PatchType("JSONPatch") {
		t.Fatalf("Unexpected PatchType: %s", *response.PatchType)
	}

	var a []interface{}
	if err := json.Unmarshal(response.Patch, &a); err != nil {
		t.Fatalf("Unmarshal error for JSON Patch: %s\n%v", string(response.Patch), err)
	}

	if string(response.Patch) != `[{"op": "replace", "path": "/spec/containers/0/image", "value": "image1@digest1"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-1-original-image", "value": "image1:tag1"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-1-mutated-image", "value": "image1@digest1"}, {"op": "replace", "path": "/spec/containers/1/image", "value": "image2@digest2"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-2-original-image", "value": "image2:tag2"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-2-mutated-image", "value": "image2@digest2"}]` {
		t.Fatalf("Unexpected JSON Patch: %s", string(response.Patch))
	}
}

func TestEvaluateAccepted(t *testing.T) {
	review := &v1beta1.AdmissionRequest{}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Error(err)
	} else {
		json.Unmarshal(b, review)
	}

	evaluator := mockImageScannerEvaluator{true, false}
	response, digestMappings, _ := Evaluate(review, &evaluator)

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

	evaluator := mockImageScannerEvaluator{false, false}
	response, digestMappings, _ := Evaluate(review, &evaluator)

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

	evaluator := mockImageScannerEvaluator{false, true}
	response, _, _ := Evaluate(review, &evaluator)

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
