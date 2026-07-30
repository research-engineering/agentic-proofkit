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
