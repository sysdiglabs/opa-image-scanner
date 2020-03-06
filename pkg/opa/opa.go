package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"k8s.io/klog"
)

func Evaluate(rules string, input interface{}) error {

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err := ast.CompileModules(map[string]string{
		"imageadmission.rego": rules,
	})

	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		return fmt.Errorf("Error marshalling input to JSON: %v", err)
	}

	klog.Infof("[rego] Input rules:\n%s", rules)
	klog.Infof("[rego] Input is:\n%s", string(b))

	ctx := context.Background()
	rego := rego.New(
		rego.Query("data.imageadmission.deny_image"),
		rego.Compiler(compiler),
		rego.Input(input),
	)

	// Run evaluation.
	rs, err := rego.Eval(ctx)

	if err != nil {
		return fmt.Errorf("Rego evaluation error: %v", err)
		// Handle error.
	}

	// Inspect results.
	klog.Infof("[rego] len: %d", len(rs))

	if len(rs) != 1 {
		return fmt.Errorf("Rego - unexpected ResultSet length: %d", len(rs))
	}

	klog.Infof("[rego] Expressions length: %d", len(rs[0].Expressions))

	if len(rs[0].Expressions) != 1 {
		return fmt.Errorf("Rego - unexpected Expressions length: %d", len(rs[0].Expressions))
	}

	klog.Infof("[rego] value: %#v", rs[0].Expressions[0].Value)

	// TODO: Some tests and how to check if it is returning an empty list (OK) or not
	if reflect.ValueOf(rs[0].Expressions[0].Value).Kind() == reflect.Slice {
		if reflect.ValueOf(rs[0].Expressions[0].Value).Len() > 0 {
			values := rs[0].Expressions[0].Value.([]interface{})
			var msgBuilder strings.Builder
			for _, value := range values {
				msgBuilder.WriteString(fmt.Sprintf("- %s\n", value))
			}
			msgList := msgBuilder.String()
			return fmt.Errorf("Image denied by OPA rules:\n%s", msgList)
		}
	}

	return nil
}
