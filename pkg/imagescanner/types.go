package imagescanner

type ScanReport struct {
	Passed      bool
	InnerReport interface{}
}

type Scanner interface {
	StartScan(imageAndTag string) (string, error)
	GetReport(imageAndTag, imageDigest string) (*ScanReport, error)
}
