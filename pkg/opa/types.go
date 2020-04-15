package opa

type GetOPARulesFunction func() (string, error)

type OPAEvaluator interface {
	Evaluate(query string, rules, data string, input interface{}) error
}

func NewEvaluator() OPAEvaluator {
	return &opaEvaluator{}
}
