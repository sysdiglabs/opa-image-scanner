package imagescanner

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
