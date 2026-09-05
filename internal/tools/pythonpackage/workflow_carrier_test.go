package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

func TestInstalledPythonWorkflowCarrierClosure(t *testing.T) {
	environment := []string{"PATH=/isolated", "PROOFKIT_TEST=1"}
	got := installedPythonWorkflowCarriers("consumer", environment, "python", "agentic-proofkit")
	environment[0] = "PATH=/mutated"
	want := []installedPythonWorkflowCarrier{
		{
			label: "python module",
			carrier: workflowsmoke.ProcessCarrier{
				Directory:   "consumer",
				Executable:  "python",
				Environment: []string{"PATH=/isolated", "PROOFKIT_TEST=1"},
				Prefix:      []string{"-m", "agentic_proofkit"},
			},
		},
		{
			label: "python console script",
			carrier: workflowsmoke.ProcessCarrier{
				Directory:   "consumer",
				Executable:  "agentic-proofkit",
				Environment: []string{"PATH=/isolated", "PROOFKIT_TEST=1"},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("installedPythonWorkflowCarriers()=%#v, want %#v", got, want)
	}
	assertPythonFunctionCalls(t, "verify.go", "verifyInstalledPythonWheel", "verifyInstalledPythonWorkflowSmokes")
}

func assertPythonFunctionCalls(t *testing.T, sourcePath string, functionName string, calleeName string) {
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
