package opaimagescanner

import (
	"encoding/json"
	"fmt"
	"image-scan-webhook/pkg/imagescanner"
	"image-scan-webhook/pkg/opa"
	"io/ioutil"
	"testing"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

type StartScanReturn struct {
	Digest string
	Error  error
}

type GetReportReturn struct {
	Report *imagescanner.ScanReport
	Error  error
}

//TODO: Check go-mock
type mockImageScanner struct {
	T *testing.T

	ExpectedImageAndTag string
	ExpectedImageDigest string

	StartScanReturn StartScanReturn
	GetReportReturn GetReportReturn

	StartScanCalled bool
	GetReportCalled bool
}

var pod = &corev1.Pod{
	Spec: corev1.PodSpec{Containers: []corev1.Container{
		{
			Name:  "TestContainer",
			Image: "mysaferegistry.io/container-image:1.01",
		},
	}},
}

func (s *mockImageScanner) StartScan(imageAndTag string) (string, error) {
	s.StartScanCalled = true

	if s.ExpectedImageAndTag != "" && s.ExpectedImageAndTag != imageAndTag {
		s.T.Fatalf("StartScan called with unexpected imageAndTag:\n%s", imageAndTag)
	}

	return s.StartScanReturn.Digest, s.StartScanReturn.Error
}

func (s *mockImageScanner) GetReport(imageAndTag, imageDigest, scanPolicyId string) (*imagescanner.ScanReport, error) {
	s.GetReportCalled = true

	if s.ExpectedImageAndTag != "" && s.ExpectedImageAndTag != imageAndTag {
		s.T.Fatalf("GetReport called with unexpected imageAndTag:\n%s", imageAndTag)
	}

	return s.GetReportReturn.Report, s.GetReportReturn.Error
}

// Verify that mockImageScanner implements imagescanner.Scanner
var _ imagescanner.Scanner = (*mockImageScanner)(nil)

type mockOPAEvaluator struct {
	EvaluateCallback func(query string, rules, data string, input interface{}) ([]opa.EvaluationResult, error)
}

func (e *mockOPAEvaluator) Evaluate(query string, rules, data string, input interface{}) ([]opa.EvaluationResult, error) {

	if e.EvaluateCallback != nil {
		return e.EvaluateCallback(query, rules, data, input)
	} else {
		return nil, nil
	}

}

// Verify that mockEvaluator implements opa.OPAEvaluator
var _ opa.OPAEvaluator = (*mockOPAEvaluator)(nil)

func mockGetOPARules() (string, error) {
	return "package mock\nmock_rules{}", nil
}

func mockGetOPAPreScanRules() (string, error) {
	return "package mock\nmock_rules{}", nil
}

func mockGetOPAData() (string, error) {
	return `{"mockData": true}`, nil
}

var mockRules, _ = mockGetOPARules()
var mockData, _ = mockGetOPAData()

func TestPreScanAccepted(t *testing.T) {

	scanner := &mockImageScanner{
		T:                   t,
		ExpectedImageAndTag: "mysaferegistry.io/container-image:1.01",
		ExpectedImageDigest: "TestDigest",
	}

	var opaEvaluator *mockOPAEvaluator
	var preOpaEvaluatorCalled int = 0

	preScanEvaluatorCallback := func(query string, rules, data string, input interface{}) ([]opa.EvaluationResult, error) {
		preOpaEvaluatorCalled++

		if rules != mockRules {
			t.Fatalf("OPAEvaluator.Evaluate called with unexpected rules:\n%s", rules)
		}

		if data != mockData {
			t.Fatalf("OPAEvaluator.Evaluate called with unexpected data:\n%s", data)

		}
		if (preOpaEvaluatorCalled) == 1 {
			if query != "data.imageadmission.allow_pod" {
				t.Fatalf("OPAEvaluator.Evaluate called with unexpected query:\n%s", query)
			}
			return []opa.EvaluationResult{
				[]opa.Expression{},
			}, nil
		} else {
			t.Fatalf("Should not call evaluator: %s", query)
			return nil, nil
		}
	}

	opaEvaluator = &mockOPAEvaluator{preScanEvaluatorCallback}

	evaluator := NewImageScannerEvaluator(scanner, opaEvaluator, mockGetOPARules, mockGetOPAPreScanRules, mockGetOPAData)

	a := loadAdmissionRequest("./assets/admission-review.json", t)

	accepted, digestMappings, err := evaluator.ScanAndEvaluate(a, pod)
	if !accepted {
		t.Fatal(err)
	}

	if len(digestMappings) > 0 {
		t.Fatalf("Unexpected digest mapping: %v", digestMappings)
	}

	if scanner.StartScanCalled {
		t.Fatalf("StartScan should not be called")
	}

	if scanner.GetReportCalled {
		t.Fatalf("GetReportCalled should not be called")
	}

	if preOpaEvaluatorCalled != 1 {
		t.Fatalf("OPAEvaluator.Evaluate was not called only once")
	}
}

func TestPreScanRejected(t *testing.T) {

	scanner := &mockImageScanner{
		T:                   t,
		ExpectedImageAndTag: "mysaferegistry.io/container-image:1.01",
		ExpectedImageDigest: "TestDigest",
	}

	var opaEvaluator *mockOPAEvaluator
	var preOpaEvaluatorCalled int = 0

	preScanEvaluatorCallback := func(query string, rules, data string, input interface{}) ([]opa.EvaluationResult, error) {
		preOpaEvaluatorCalled++

		if rules != mockRules {
			t.Fatalf("OPAEvaluator.Evaluate called with unexpected rules:\n%s", rules)
		}

		if data != mockData {
			t.Fatalf("OPAEvaluator.Evaluate called with unexpected data:\n%s", data)

		}
		if (preOpaEvaluatorCalled) == 1 {
			if query != "data.imageadmission.allow_pod" {
				t.Fatalf("OPAEvaluator.Evaluate called with unexpected query:\n%s", query)
			}
			return []opa.EvaluationResult{}, nil
		} else if (preOpaEvaluatorCalled) == 2 {
			if query != "data.imageadmission.deny_pod" {
				t.Fatalf("OPAEvaluator.Evaluate called with unexpected query:\n%s", query)
			}
			return []opa.EvaluationResult{
				[]opa.Expression{
					{Text: "dummy", Value: []interface{}{"Rejected in pre-scan"}},
				},
			}, nil
		} else {
			t.Fatalf("Should not call evaluator: %s", query)
			return nil, nil
		}
	}

	opaEvaluator = &mockOPAEvaluator{preScanEvaluatorCallback}

	evaluator := NewImageScannerEvaluator(scanner, opaEvaluator, mockGetOPARules, mockGetOPAPreScanRules, mockGetOPAData)

	a := loadAdmissionRequest("./assets/admission-review.json", t)

	accepted, digestMappings, err := evaluator.ScanAndEvaluate(a, pod)

	if accepted {
		t.Fatal("Should not be accepted")
	}

	if len(digestMappings) > 0 {
		t.Fatalf("Unexpected digest mapping: %v", digestMappings)
	}

	if scanner.StartScanCalled {
		t.Fatalf("StartScan should not be called")
	}

	if scanner.GetReportCalled {
		t.Fatalf("GetReportCalled should not be called")
	}

	if preOpaEvaluatorCalled != 2 {
		t.Fatalf("OPAEvaluator.Evaluate was not called only twice")
	}

	if accepted || len(err) != 1 || err[0] != "Pre-scan rejected. Reasons: Rejected in pre-scan" {
		t.Fatalf("Unexpected error: %v", err)
	}

}

func TestEvaluationAccepts(t *testing.T) {

	report := &imagescanner.ScanReport{
		Status: imagescanner.StatusAccepted,
	}

	scanner := &mockImageScanner{
		T:                   t,
		ExpectedImageAndTag: "mysaferegistry.io/container-image:1.01",
		ExpectedImageDigest: "TestDigest",
		StartScanReturn:     StartScanReturn{Digest: "TestDigest", Error: nil},
		GetReportReturn:     GetReportReturn{Report: report, Error: nil}}

	var opaEvaluator *mockOPAEvaluator
	var preOpaEvaluatorCalled int = 0
	var opaEvaluatorCalled bool

	evaluatorCallback := func(query string, rules, data string, input interface{}) ([]opa.EvaluationResult, error) {
		opaEvaluatorCalled = true

		if query != "data.imageadmission.deny_image" {
			t.Fatalf("OPAEvaluator.Evaluate called with unexpected query:\n%s", query)
		}

		if rules != mockRules {
			t.Fatalf("OPAEvaluator.Evaluate called with unexpected rules:\n%s", rules)
		}

		if data != mockData {
			t.Fatalf("OPAEvaluator.Evaluate called with unexpected data:\n%s", data)
		}

		return []opa.EvaluationResult{
			[]opa.Expression{
				{Text: "dummy", Value: []interface{}{}},
			},
		}, nil
	}

	preScanEvaluatorCallback := func(query string, rules, data string, input interface{}) ([]opa.EvaluationResult, error) {
		preOpaEvaluatorCalled++

		if rules != mockRules {
			t.Fatalf("OPAEvaluator.Evaluate called with unexpected rules:\n%s", rules)
		}

		if data != mockData {
			t.Fatalf("OPAEvaluator.Evaluate called with unexpected data:\n%s", data)

		}
		if (preOpaEvaluatorCalled) == 1 {
			if query != "data.imageadmission.allow_pod" {
				t.Fatalf("OPAEvaluator.Evaluate called with unexpected query:\n%s", query)
			}
			return []opa.EvaluationResult{}, nil
		} else {
			if query != "data.imageadmission.deny_pod" {
				t.Fatalf("OPAEvaluator.Evaluate called with unexpected query:\n%s", query)
			}
			opaEvaluator.EvaluateCallback = evaluatorCallback
			return []opa.EvaluationResult{
				[]opa.Expression{
					{Text: "dummy", Value: []interface{}{}},
				},
			}, nil
		}

	}

	opaEvaluator = &mockOPAEvaluator{preScanEvaluatorCallback}

	evaluator := NewImageScannerEvaluator(scanner, opaEvaluator, mockGetOPARules, mockGetOPAPreScanRules, mockGetOPAData)

	a := loadAdmissionRequest("./assets/admission-review.json", t)

	accepted, digestMappings, err := evaluator.ScanAndEvaluate(a, pod)
	if !accepted {
		t.Fatal(err)
	}

	if digestMappings["mysaferegistry.io/container-image:1.01"] != "TestDigest" {
		t.Fatalf("Unexpected digest mapping: %v", digestMappings)
	}

	if !scanner.StartScanCalled {
		t.Fatalf("StartScan was not called")
	}

	if !scanner.GetReportCalled {
		t.Fatalf("GetReportCalled was not called")
	}

	if !opaEvaluatorCalled {
		t.Fatalf("OPAEvaluator.Evaluate was not called")
	}
}

func TestNilAdmissionReview(t *testing.T) {

	scanner := &mockImageScanner{}
	opaEvaluator := &mockOPAEvaluator{}

	evaluator := NewImageScannerEvaluator(scanner, opaEvaluator, mockGetOPARules, mockGetOPAPreScanRules, mockGetOPAData)

	accepted, _, err := evaluator.ScanAndEvaluate(nil, nil)
	if accepted || len(err) != 1 || err[0] != "Admission request is <nil>" {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestEmptyAdmissionReview(t *testing.T) {
	report := &imagescanner.ScanReport{
		Status: imagescanner.StatusAccepted,
	}

	scanner := &mockImageScanner{
		StartScanReturn: StartScanReturn{Digest: "", Error: fmt.Errorf("Some error - forced in test")},
		GetReportReturn: GetReportReturn{Report: report, Error: nil}}
	opaEvaluator := &mockOPAEvaluator{}

	evaluator := NewImageScannerEvaluator(scanner, opaEvaluator, mockGetOPARules, mockGetOPAPreScanRules, mockGetOPAData)
	a := &v1beta1.AdmissionRequest{}

	accepted, _, err := evaluator.ScanAndEvaluate(a, nil)
	if accepted || len(err) != 1 || err[0] != "Pod data is <nil>" {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestStartScanFails(t *testing.T) {
	report := &imagescanner.ScanReport{
		Status: imagescanner.StatusAccepted,
	}

	scanner := &mockImageScanner{
		StartScanReturn: StartScanReturn{Digest: "", Error: fmt.Errorf("Some error")},
		GetReportReturn: GetReportReturn{Report: report, Error: nil}}

	opaEvaluatorCalled := 0
	opaEvaluator := &mockOPAEvaluator{EvaluateCallback: func(query string, rules, data string, input interface{}) ([]opa.EvaluationResult, error) {
		opaEvaluatorCalled++
		if opaEvaluatorCalled == 1 {
			return []opa.EvaluationResult{}, nil
		} else if opaEvaluatorCalled == 2 {
			return []opa.EvaluationResult{
				[]opa.Expression{
					{Text: "dummy", Value: []interface{}{}},
				},
			}, nil
		} else {
			opaInput := input.(OPAInput)
			if opaInput.ScanReport.Status != imagescanner.StatusScanFailed {
				t.Fatalf("OPAEvaluator.Evaluate did not receive a Scan Report with ScanFailed status")
			}
			return []opa.EvaluationResult{
				[]opa.Expression{
					{Text: "dummy", Value: []interface{}{}},
				},
			}, nil
		}
	}}

	evaluator := NewImageScannerEvaluator(scanner, opaEvaluator, mockGetOPARules, mockGetOPAPreScanRules, mockGetOPAData)

	a := loadAdmissionRequest("./assets/admission-review.json", t)

	accepted, _, err := evaluator.ScanAndEvaluate(a, pod)
	if !accepted {
		t.Fatal(err)
	}

	if !scanner.StartScanCalled {
		t.Fatalf("StartScan was not called")
	}

	if scanner.GetReportCalled {
		t.Fatalf("GetReportCalled should NOT be called")
	}

	if opaEvaluatorCalled != 3 {
		t.Fatalf("OPAEvaluator.Evaluate was NOT called")
	}
}

func TestGetReportFails(t *testing.T) {

	scanner := &mockImageScanner{
		ExpectedImageDigest: "sha256:somedigest",
		StartScanReturn:     StartScanReturn{Digest: "sha256:somedigest", Error: nil},
		GetReportReturn:     GetReportReturn{Report: nil, Error: fmt.Errorf("Some error")}}

	opaEvaluatorCalled := 0
	opaEvaluator := &mockOPAEvaluator{EvaluateCallback: func(query string, rules, data string, input interface{}) ([]opa.EvaluationResult, error) {
		opaEvaluatorCalled++
		if opaEvaluatorCalled == 1 {
			return []opa.EvaluationResult{}, nil
		} else if opaEvaluatorCalled == 2 {
			return []opa.EvaluationResult{
				[]opa.Expression{
					{Text: "dummy", Value: []interface{}{}},
				},
			}, nil
		} else {
			opaInput := input.(OPAInput)
			if opaInput.ScanReport.Status != imagescanner.StatusReportNotAvailable {
				t.Fatalf("OPAEvaluator.Evaluate did not receive a Scan Report with StatusReportNotAvailable status")
			}
			return []opa.EvaluationResult{
				[]opa.Expression{
					{Text: "dummy", Value: []interface{}{}},
				},
			}, nil
		}
	}}

	evaluator := NewImageScannerEvaluator(scanner, opaEvaluator, mockGetOPARules, mockGetOPAPreScanRules, mockGetOPAData)

	a := loadAdmissionRequest("./assets/admission-review.json", t)

	accepted, digestMappings, err := evaluator.ScanAndEvaluate(a, pod)
	if !accepted {
		t.Fatal(err)
	}

	if digestMappings["mysaferegistry.io/container-image:1.01"] != "sha256:somedigest" {
		t.Fatalf("Unexpected digest mapping: %v", digestMappings)
	}

	if !scanner.StartScanCalled {
		t.Fatalf("StartScan was not called")
	}

	if !scanner.GetReportCalled {
		t.Fatalf("GetReportCalled was not called")
	}

	if opaEvaluatorCalled != 3 {
		t.Fatalf("OPAEvaluator.Evaluate was NOT called")
	}
}

func TestEvaluationRejects(t *testing.T) {

	report := &imagescanner.ScanReport{
		Status: imagescanner.StatusAccepted,
	}

	scanner := &mockImageScanner{
		T:                   t,
		ExpectedImageAndTag: "mysaferegistry.io/container-image:1.01",
		ExpectedImageDigest: "TestDigest",
		StartScanReturn:     StartScanReturn{Digest: "TestDigest", Error: nil},
		GetReportReturn:     GetReportReturn{Report: report, Error: nil}}

	opaEvaluatorCalled := 0
	opaEvaluator := &mockOPAEvaluator{EvaluateCallback: func(query string, rules, data string, input interface{}) ([]opa.EvaluationResult, error) {
		opaEvaluatorCalled++
		if opaEvaluatorCalled == 1 {
			return []opa.EvaluationResult{}, nil
		} else if opaEvaluatorCalled == 2 {
			return []opa.EvaluationResult{
				[]opa.Expression{
					{Text: "dummy", Value: []interface{}{}},
				},
			}, nil
		} else {
			opaInput := input.(OPAInput)
			if opaInput.ScanReport.Status != imagescanner.StatusAccepted {
				t.Fatalf("OPAEvaluator.Evaluate did not receive a Scan Report with StatusAccepted status")
			}
			return []opa.EvaluationResult{
				[]opa.Expression{
					{Text: "dummy", Value: []interface{}{"Reject this container"}},
				},
			}, nil
		}
	}}

	evaluator := NewImageScannerEvaluator(scanner, opaEvaluator, mockGetOPARules, mockGetOPAPreScanRules, mockGetOPAData)

	a := loadAdmissionRequest("./assets/admission-review.json", t)

	accepted, _, err := evaluator.ScanAndEvaluate(a, pod)
	if accepted {
		t.Errorf("Should not be accepted")
	}
	if len(err) != 1 {
		t.Errorf("More errors than expected:\n%s", err)
	}
	if err[0] != "Image 'mysaferegistry.io/container-image:1.01' for container 'TestContainer' failed scan policy check: Reject this container" {
		t.Errorf("Unexpected evaluation error:\n *%v*", err[0])
	}

}

func loadAdmissionRequest(path string, t *testing.T) *v1beta1.AdmissionRequest {
	a := &v1beta1.AdmissionRequest{}
	if b, err := ioutil.ReadFile(path); err != nil {
		t.Fatal(err)
	} else {
		json.Unmarshal(b, a)
	}

	return a
}
