package opa

import (
	"context"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"k8s.io/klog"
)

func Test(input interface{}) error {

	// Define a simple policy.
	module := `
		package imageadmission

		default allow = false

		allow {
			input.identity = "admin"
		}

		allow {
			input.method = "GET"
		}
	`

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err := ast.CompileModules(map[string]string{
		"imageadmission.rego": module,
	})

	if err != nil {
		return err
	}

	ctx := context.Background()
	rego := rego.New(
		rego.Query("data.imageadmission.allow"),
		rego.Compiler(compiler),
		rego.Input(input),
	)

	// Run evaluation.
	rs, err := rego.Eval(ctx)

	if err != nil {
		return err
		// Handle error.
	}

	// Inspect results.
	klog.Infof("[rego] len:", len(rs))
	klog.Infof("[rego] value:", rs[0].Expressions[0].Value)

	return nil
}
