package anchore

type AnchoreClient struct {
	baseUrl     string
	secureToken string
}

type Image struct {
	ImageDigest string `json:"imageDigest"`
}

type ScanReports []map[string]map[string][]ScanReport

type ScanReport struct {
	Status         string
	PolicyId       string `json:"policyId"`
	LastEvaluation string `json:"last_evaluation"`
	Detail         interface{}
}
