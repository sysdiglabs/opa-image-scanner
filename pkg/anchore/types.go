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

type AnchoreConfig struct {
	EndpointURL string `yaml:"ANCHORE_CLI_URL"`
	Token       string `yaml:"ANCHORE_CLI_TOKEN"`
}
