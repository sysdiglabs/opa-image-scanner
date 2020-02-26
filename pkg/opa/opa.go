package opa

import (
	"context"
	"fmt"
	"reflect"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"k8s.io/klog"
)

func Test(input interface{}) error {

	// Define a simple policy.
	module := `
	package imageadmission

	allow_image {
		input.message == "hello"
	}

	allow_image {
		input.ScanReport.Status == "passatio"
	}
	
	deny_image[msg] {
		not allow_image
		msg := "Denying images by default"
	}
	
	deny_image[msg] {
		not allow_image
		msg := "Because I want to deny"
	}

	deny_image[msg] {
		not allow_image
		msg := input.ScanReport.Status
	}
	`

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err := ast.CompileModules(map[string]string{
		"imageadmission.rego": module,
	})

	if err != nil {
		return err
	}

	klog.Infof("[rego] Input is %s", input)

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

	klog.Infof("[rego] value: %s", rs[0].Expressions[0].Value)

	// TODO: Some tests and how to check if it is returning an empty list (OK) or not
	if reflect.ValueOf(rs[0].Expressions[0].Value).Kind() == reflect.Slice {
		if reflect.ValueOf(rs[0].Expressions[0].Value).Len() > 0 {
			return fmt.Errorf("Image denied by OPA rules: %s", rs[0].Expressions[0].Value)
		}
	}

	// if len(rs[0].Expressions[0]) > 0 {
	// 	return fmt.Errorf("Image denied by OPA rules: %s", rs[0].Expressions[0].Value)
	// }

	return nil
}
