package gotestsource

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestHasSkipDistinguishesTestingParameterCalls(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "skip", body: `t.Skip("blocked")`, want: true},
		{name: "skipf", body: `t.Skipf("blocked: %s", "reason")`, want: true},
		{name: "direct alias", body: `u := t; u.Skip("blocked")`, want: true},
		{name: "declared alias", body: `var u = t; u.SkipNow()`, want: true},
		{name: "reassigned alias", body: `var u *testing.T; u = t; u.Skip("blocked")`, want: true},
		{name: "helper skip", body: `helper.Skip()`, want: false},
		{name: "ordinary assertion", body: `t.Fatal("failed")`, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := "package fixture\nimport \"testing\"\nfunc TestWitness(t *testing.T) { " + test.body + " }\n"
			file, err := parser.ParseFile(token.NewFileSet(), "fixture_test.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			function := file.Decls[1].(*ast.FuncDecl)
			if got := HasSkip(function); got != test.want {
				t.Fatalf("HasSkip()=%v, want %v", got, test.want)
			}
		})
	}
}

func TestHasFailureCapableAssertionSyntaxFollowsTestingHandleAlias(t *testing.T) {
	source := `package fixture
import "testing"
func TestWitness(t *testing.T) { u := t; u.Fatal("failed") }
`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture_test.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !HasFailureCapableAssertionSyntax(file.Decls[1].(*ast.FuncDecl)) {
		t.Fatal("failure-capable assertion through a testing handle alias was not detected")
	}
}

func TestHasFailureCapableAssertionCandidateRejectsVacuousBody(t *testing.T) {
	for _, test := range []struct {
		body string
		want bool
	}{
		{body: `_ = t`, want: false},
		{body: `helper.Fatal("failed")`, want: false},
		{body: `if false { t.Fatal("unreachable") }`, want: false},
		{body: `_ = func() { t.Fatal("not invoked") }`, want: false},
		{body: `t.Fatalf("failed: %d", 1)`, want: true},
	} {
		source := "package fixture\nimport \"testing\"\nfunc TestWitness(t *testing.T) { " + test.body + " }\n"
		file, err := parser.ParseFile(token.NewFileSet(), "fixture_test.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		function := file.Decls[1].(*ast.FuncDecl)
		if got := HasFailureCapableAssertionCandidate(function); got != test.want {
			t.Fatalf("HasFailureCapableAssertionCandidate(%q)=%v, want %v", test.body, got, test.want)
		}
	}
}

func TestHasFailureCapableAssertionCandidateFollowsTestingHelperCalls(t *testing.T) {
	source := `package fixture
import "testing"
func assertWitness(t *testing.T) { t.Fatal("failed") }
func TestWitness(t *testing.T) { assertWitness(t) }
`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture_test.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok {
			functions[function.Name.Name] = function
		}
	}
	if !HasFailureCapableAssertionCandidate(functions["TestWitness"], functions) {
		t.Fatal("reachable helper assertion was not detected")
	}
}

func TestHasFailureCapableAssertionCandidateAlignsArgumentsAfterUnnamedParameters(t *testing.T) {
	source := `package fixture
import "testing"
func assertWitness(string, t *testing.T) { t.Fatal("failed") }
func TestWitness(t *testing.T) { assertWitness("context", t) }
`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture_test.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok {
			functions[function.Name.Name] = function
		}
	}
	if !HasFailureCapableAssertionCandidate(functions["TestWitness"], functions) {
		t.Fatal("unnamed helper parameter shifted testing.T argument propagation")
	}
}

func TestHasFailureCapableAssertionCandidateRejectsTransitiveSkip(t *testing.T) {
	source := `package fixture
import "testing"
func skipWitness(t *testing.T) { t.Skip("blocked"); t.Fatal("unreachable") }
func TestWitness(t *testing.T) { skipWitness(t) }
`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture_test.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok {
			functions[function.Name.Name] = function
		}
	}
	if HasFailureCapableAssertionCandidate(functions["TestWitness"], functions) {
		t.Fatal("helper assertion after t.Skip was admitted as an executable candidate")
	}
}

func TestHasFailureCapableAssertionCandidateRejectsAliasedSkip(t *testing.T) {
	source := `package fixture
import "testing"
func skipWitness(t *testing.T) { var u *testing.T; u = t; u.Skip("blocked"); t.Fatal("unreachable") }
func TestWitness(t *testing.T) { alias := t; skipWitness(alias) }
`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture_test.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok {
			functions[function.Name.Name] = function
		}
	}
	if HasFailureCapableAssertionCandidate(functions["TestWitness"], functions) {
		t.Fatal("assertion after an aliased helper skip was admitted as an executable candidate")
	}
}
