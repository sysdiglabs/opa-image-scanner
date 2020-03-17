package anchore

import (
	"fmt"
	"image-scan-webhook/pkg/imagescanner"
	"strings"

	"k8s.io/klog"
)

func (c *anchoreClient) StartScan(imageAndTag string) (digest string, err error) {
	digest, err = c.addImage(imageAndTag)
	if err != nil {
		klog.Errorf("[Anchore] addImage error: %s", err)
		return "", fmt.Errorf("unable to obtain image digest: %v", err)
	}

	return
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
