package admissionserver

import (
	"encoding/json"
	"image-scan-webhook/pkg/opaimagescanner"
	"io/ioutil"
	"testing"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type mockImageScannerEvaluator struct {
	Accepted           bool
	AllNull            bool
	IncludeAnnotations bool
}

func (m *mockImageScannerEvaluator) Evaluate(a *v1beta1.AdmissionRequest) (accepted bool, digestMappings map[string]string, pod *corev1.Pod, errors []string) {
	accepted = m.Accepted
	errors = []string{"error1", "error2"}
	if !m.AllNull {
		digestMappings = map[string]string{"image1:tag": "digest1", "image2:tag": "digest2"}
		pod = &corev1.Pod{
			Spec: corev1.PodSpec{Containers: []corev1.Container{
				{Image: "image1:tag"},
				{Image: "image2:tag"},
			}},
		}

		if m.IncludeAnnotations {
			pod.ObjectMeta = v1.ObjectMeta{
				Annotations: map[string]string{"test-annotation": "test-value"},
			}
		}
	}
	return
}

// Verify that mockImageScannerEvaluator implements opaimagescanner.AdmissionEvaluator.
var _ opaimagescanner.AdmissionEvaluator = (*mockImageScannerEvaluator)(nil)

func TestMutationHookAdmit(t *testing.T) {
	hook := &mutationHook{evaluator: &mockImageScannerEvaluator{true, false, false}}

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

	if string(response.Patch) != `[{"op": "add", "path": "/metadata/annotations", "value": {}}, {"op": "replace", "path": "/spec/containers/0/image", "value": "image1@digest1"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-1-original-image", "value": "image1:tag"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-1-mutated-image", "value": "image1@digest1"}, {"op": "replace", "path": "/spec/containers/1/image", "value": "image2@digest2"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-2-original-image", "value": "image2:tag"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-2-mutated-image", "value": "image2@digest2"}]` {
		t.Fatalf("Unexpected JSON Patch: %s", string(response.Patch))
	}
}

func TestMutationHookPreserveAnnotations(t *testing.T) {
	hook := &mutationHook{evaluator: &mockImageScannerEvaluator{true, false, true}}

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

	if string(response.Patch) != `[{"op": "replace", "path": "/spec/containers/0/image", "value": "image1@digest1"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-1-original-image", "value": "image1:tag"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-1-mutated-image", "value": "image1@digest1"}, {"op": "replace", "path": "/spec/containers/1/image", "value": "image2@digest2"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-2-original-image", "value": "image2:tag"}, {"op": "add", "path": "/metadata/annotations/admission.sysdig.com~1container-2-mutated-image", "value": "image2@digest2"}]` {
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

	evaluator := mockImageScannerEvaluator{true, false, false}
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

	if digestMappings["image1:tag"] != "digest1" {
		t.Fatalf("Unexpected mapping: %s", digestMappings["image1:tag"])
	}

	if digestMappings["image2:tag"] != "digest2" {
		t.Fatalf("Unexpected mapping: %s", digestMappings["image2:tag"])
	}
}

func TestEvaluateRejected(t *testing.T) {
	review := &v1beta1.AdmissionRequest{}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Error(err)
	} else {
		json.Unmarshal(b, review)
	}

	evaluator := mockImageScannerEvaluator{false, false, false}
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

	if digestMappings["image1:tag"] != "digest1" {
		t.Fatalf("Unexpected mapping: %s", digestMappings["image1:tag"])
	}

	if digestMappings["image2:tag"] != "digest2" {
		t.Fatalf("Unexpected mapping: %s", digestMappings["image2:tag"])
	}
}

func TestEvaluateRejectedNilPod(t *testing.T) {
	review := &v1beta1.AdmissionRequest{}

	if b, err := ioutil.ReadFile("./assets/admission-review.json"); err != nil {
		t.Error(err)
	} else {
		json.Unmarshal(b, review)
	}

	evaluator := mockImageScannerEvaluator{false, true, false}
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
