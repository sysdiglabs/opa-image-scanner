package anchore

import (
	"fmt"
	"image-scan-webhook/pkg/imagescanner"
	"strings"
)

func (c *anchoreClient) StartScan(imageAndTag string) (string, error) {
	if digest, err := c.getImageDigest(imageAndTag); err != nil {
		return "", fmt.Errorf("unable to obtain image digest: %v", err)
	} else {
		return digest, nil
	}

}

func (c *anchoreClient) GetReport(imageAndTag, imageDigest string) (*imagescanner.ScanReport, error) {
	innerReport, err := c.getReport(imageDigest, imageAndTag)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain scan report: %v", err)
	}

	report := &imagescanner.ScanReport{
		ImageAndTag: imageAndTag,
		InnerReport: innerReport,
	}

	if strings.ToLower(innerReport.Status) == "pass" {
		report.Status = imagescanner.StatusAccepted
	} else {
		report.Status = imagescanner.StatusRejected
	}

	return report, nil
}
