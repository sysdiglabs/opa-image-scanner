package anchore

type Check struct {
	LastEvaluation string `json:"last_evaluation"`
	PolicyId       string `json:"policy_id"`
	Status         string `json:"status"`
}

type Image struct {
	ImageDigest string `json:"imageDigest"`
}

type SHAResult struct {
	Status string
}

type ScanReports []map[string]map[string][]ScanReport

type ScanReport struct {
	Status         string
	PolicyId       string `json:"policyId"`
	LastEvaluation string `json:"last_evaluation"`
	Detail         interface{}
}

type AnchoreConfig struct {
	EndpointURL string `yaml:"ANCHORE_CLI_URL"`
	Token       string `yaml:"ANCHORE_CLI_TOKEN"`
}
