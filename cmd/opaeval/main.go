package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

func main() {

	if len(os.Args) < 5 {
		log.Fatal("Usage: opaeval input.json data.json rules.rego query")
	}

	query := os.Args[4]
	var err error

	var compiler *ast.Compiler
	if compiler, err = ast.CompileModules(map[string]string{
		"rules.rego": getFileContent(os.Args[3]),
	}); err != nil {
		log.Fatal(err)
	}

	var input interface{}
	if input, err = parseInput(getFileContent(os.Args[1])); err != nil {
		log.Fatal(err)
	}

	var store storage.Store
	if store, err = parseData(getFileContent(os.Args[2])); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	rego := rego.New(
		rego.Query(query),
		rego.Input(input),
		rego.Compiler(compiler),
		rego.Store(store),
	)

	rs, err := rego.Eval(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("RS len:", len(rs))
	for i := range rs {
		fmt.Printf("RS[%d] Bindings:\n", i)
		print_iface(rs[i].Bindings)
		fmt.Printf("RS[%d] Expressions:\n", i)
		for j := range rs[i].Expressions {
			fmt.Printf("  Expr %d text:  %s\n", i, rs[i].Expressions[j].Text)
			fmt.Printf("  Expr %d loc:   %d:%d\n", i, rs[i].Expressions[j].Location.Row, rs[i].Expressions[j].Location.Col)
			fmt.Printf("  Expr %d value:\n", i)
			print_iface(rs[i].Expressions[j].Value)
			fmt.Println()
		}
		fmt.Println()

	}
}

func print_iface(i interface{}) {
	if t, ok := i.(rego.Vars); ok {
		print_map(t)
	} else if t, ok := i.(map[string]interface{}); ok {
		print_map(t)
	} else if t, ok := i.([]interface{}); ok {
		fmt.Printf("[")
		for idx := range t {
			print_iface(t[idx])
			fmt.Printf(",")
		}
		fmt.Printf("]")
	} else if t, ok := i.(string); ok {
		fmt.Printf("\"%s\"", t)
	} else {
		fmt.Printf("%+v", i)
	}
}

func print_map(m map[string]interface{}) {
	for k := range m {
		fmt.Printf("  %s: ", k)
		print_iface(m[k])
		fmt.Println()
	}
}

func getFileContent(filePath string) string {
	fileContents, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal("Rule compilation error", err)
	}

	return string(fileContents)
}

func parseInput(input string) (interface{}, error) {
	var jsonData map[string]interface{}

	err := json.Unmarshal([]byte(input), &jsonData)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

func parseData(data string) (storage.Store, error) {
	var jsonData map[string]interface{}

	err := json.Unmarshal([]byte(data), &jsonData)
	if err != nil {
		return nil, err
	}

	store := inmem.NewFromObject(jsonData)
	return store, nil
}
