package opa

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"k8s.io/klog"
)

func (o *opaEvaluator) Evaluate(query, rules, data string, input interface{}) ([]EvaluationResult, error) {

	rs, err := evaluateRules(query, rules, data, input)
	if err != nil {
		return nil, fmt.Errorf("Rego evaluation error: %v", err)
	}

	return evaluateResults(rs), nil
}

func evaluateRules(query, rules, data string, input interface{}) (rego.ResultSet, error) {

	store, err := parseData(data)
	if err != nil {
		return nil, fmt.Errorf("Error parsing data:\n%v", err)
	}

	compiler, err := compileRules(rules)
	if err != nil {
		return nil, fmt.Errorf("Rule compilation error:\n%v", err)
	}

	b, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("Error marshalling input to JSON: %v", err)
	}

	klog.V(3).Infof("[rego] Input is:\n%s", string(b))

	klog.V(3).Infof("[rego] Expression to evaluate:\n%s", query)

	ctx := context.Background()
	rego := rego.New(
		rego.Query(query),
		rego.Compiler(compiler),
		rego.Input(input),
		rego.Store(store),
	)

	// Run evaluation.
	return rego.Eval(ctx)
}

func parseData(data string) (storage.Store, error) {
	klog.V(3).Infof("[rego] Data is:\n%s", data)
	var jsonData map[string]interface{}

	err := json.Unmarshal([]byte(data), &jsonData)
	if err != nil {
		return nil, err
	}

	store := inmem.NewFromObject(jsonData)
	return store, nil
}

func compileRules(rules string) (*ast.Compiler, error) {
	klog.V(3).Infof("[rego] Rules are:\n%s", rules)

	// Compile the module. The keys are used as identifiers in error messages.
	return ast.CompileModules(map[string]string{
		"rules.rego": rules,
	})
}

func evaluateResults(rs rego.ResultSet) []EvaluationResult {

	er := make([]EvaluationResult, len(rs))
	klog.V(3).Infof("[rego] len(ResultSet) = %d", len(rs))

	for i := range rs {
		klog.V(3).Infof("[rego] len(rs[%d].Expressions) = %d", i, len(rs[i].Expressions))
		er[i] = make([]Expression, len(rs[i].Expressions))
		for j := range rs[i].Expressions {
			klog.V(3).Infof("[rego]   rs[%d].Expression[%d]: %s=%v", i, j, rs[i].Expressions[j].Text, rs[i].Expressions[j].Value)
			er[i][j].Text = rs[i].Expressions[j].Text
			er[i][j].Value = rs[i].Expressions[j].Value
		}
	}

	return er

}
