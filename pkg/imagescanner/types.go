package imagescanner

import (
	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

const StatusAccepted = "accepted"
const StatusRejected = "rejected"
const StatusScanFailed = "scan_failed"
const StatusReportNotAvailable = "report_not_available"

type ScanReport struct {
	ImageAndTag string
	Status      string
	InnerReport interface{}
}

type Scanner interface {
	StartScan(imageAndTag string) (string, error)
	GetReport(imageAndTag, imageDigest string) (*ScanReport, error)
}

type ImageScannerAdmissionEvaluator interface {
	ScanAndEvaluate(a *v1beta1.AdmissionRequest, pod *corev1.Pod) (accepted bool, digestMappings map[string]string, rejectReasons []string)
}
