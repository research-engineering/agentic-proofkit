package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

func TestInstalledNPMWorkflowCarrierClosure(t *testing.T) {
	consumer := filepath.Join("consumer", "root")
	want := workflowsmoke.ProcessCarrier{
		Directory:  consumer,
		Executable: "npm",
		Prefix:     []string{"--silent", "exec", "--offline", "--", "agentic-proofkit"},
	}
	if got := installedNPMWorkflowCarrier(consumer); !reflect.DeepEqual(got, want) {
		t.Fatalf("installedNPMWorkflowCarrier()=%#v, want %#v", got, want)
	}
	assertFunctionCalls(t, "main.go", "verifyInstalledJSONABI", "verifyInstalledNPMWorkflowSmoke")
}

func assertFunctionCalls(t *testing.T, sourcePath string, functionName string, calleeName string) {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), sourcePath, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != functionName || function.Body == nil {
			continue
		}
		calls := 0
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee, ok := call.Fun.(*ast.Ident)
			if ok && callee.Name == calleeName {
				calls++
			}
			return true
		})
		if calls != 1 {
			t.Fatalf("%s must call %s exactly once, got %d", functionName, calleeName, calls)
		}
		return
	}
	t.Fatalf("function %s is missing from %s", functionName, sourcePath)
}
