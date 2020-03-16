package anchore

import (
	"image-scan-webhook/pkg/imagescanner"
	"net/http"
)

type anchoreClient struct {
	baseUrl     string
	secureToken string
	httpClient  *http.Client
}

// Verify that anchoreClient implements imagescanner.Scanner
var _ imagescanner.Scanner = (*anchoreClient)(nil)

type imageInfo struct {
	ImageDigest string `json:"imageDigest"`
}

type scanReports []map[string]map[string][]ScanReport

type ScanReport struct {
	Status         string
	PolicyId       string `json:"policyId"`
	LastEvaluation string `json:"last_evaluation"`
	Detail         interface{}
}
