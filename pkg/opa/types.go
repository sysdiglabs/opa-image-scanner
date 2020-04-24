package opa

type Expression struct {
	Text  string
	Value interface{}
}

type EvaluationResult []Expression

type GetOPARulesFunction func() (string, error)

type OPAEvaluator interface {
	Evaluate(query string, rules, data string, input interface{}) ([]EvaluationResult, error)
}

func NewEvaluator() OPAEvaluator {
	return &opaEvaluator{}
}
