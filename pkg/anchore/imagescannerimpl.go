package anchore

import (
	"fmt"
	"image-scan-webhook/pkg/imagescanner"
	"strings"
)

func (c *AnchoreClient) StartScan(imageAndTag string) (string, error) {
	if digest, err := c.getImageDigest(imageAndTag); err != nil {
		return "", fmt.Errorf("unable to obtain image digest: %v", err)
	} else {
		return digest, nil
	}

}

func (c *AnchoreClient) GetReport(imageAndTag, imageDigest string) (*imagescanner.ScanReport, error) {
	report, err := c.getReport(imageDigest, imageAndTag)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain scan report: %v", err)
	}

	return &imagescanner.ScanReport{
		Passed:      strings.ToLower(report.Status) == "pass",
		InnerReport: report,
	}, nil
}
