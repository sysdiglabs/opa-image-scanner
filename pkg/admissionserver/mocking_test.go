package admissionserver

import (
	"image-scan-webhook/pkg/imagescanner"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

type mockPreScanEvaluator struct {
	Accept bool
	Reject bool
}

type mockImageScannerEvaluator struct {
	Accepted              bool
	AllNull               bool
	ScanAndEvaluateCalled bool
}

func (m *mockImageScannerEvaluator) ScanAndEvaluate(a *v1beta1.AdmissionRequest, pod *corev1.Pod) (accepted bool, digestMappings map[string]string, rejectReasons []string) {
	m.ScanAndEvaluateCalled = true
	accepted = m.Accepted

	if !accepted {
		rejectReasons = []string{"error1", "error2"}
	}

	if !m.AllNull {
		digestMappings = map[string]string{"image1:tag1": "digest1", "image2:tag2": "digest2"}
	}
	return
}

// Verify that mockImageScannerEvaluator implements opaimagescanner.ImageScannerAdmissionEvaluator.
var _ imagescanner.ImageScannerAdmissionEvaluator = (*mockImageScannerEvaluator)(nil)
