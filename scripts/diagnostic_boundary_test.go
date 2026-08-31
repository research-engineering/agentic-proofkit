package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestToolDiagnosticBoundaryRejectsDirectDynamicStderrWrites(t *testing.T) {
	repositoryRoot := sourceHygieneRepoRoot(t)
	for _, scope := range []string{"internal/tools", "scripts"} {
		root := filepath.Join(repositoryRoot, scope)
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			if dynamicStderrWriteCount(parsed) != 0 {
				t.Errorf("%s writes dynamic stderr without the diagnostic owner", path)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	for _, test := range []struct {
		name   string
		source string
		want   int
	}{
		{name: "fixed literal", source: `package main; import ("fmt"; "os"); func main(){ fmt.Fprintln(os.Stderr, "fixed usage") }`, want: 0},
		{name: "raw error", source: `package main; import ("fmt"; "os"); func main(){ var err error; fmt.Fprintln(os.Stderr, err) }`, want: 1},
		{name: "formatted dynamic value", source: `package main; import ("fmt"; "os"); func main(){ value := "caller"; fmt.Fprintf(os.Stderr, "failed: %s", value) }`, want: 1},
		{name: "aliased imports", source: `package main; import (f "fmt"; system "os"); func main(){ var err error; f.Fprintln(system.Stderr, err) }`, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := parser.ParseFile(token.NewFileSet(), "fixture.go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := dynamicStderrWriteCount(parsed); got != test.want {
				t.Fatalf("dynamic stderr write count=%d, want %d", got, test.want)
			}
		})
	}
}

func dynamicStderrWriteCount(file *ast.File) int {
	importNames := map[string]string{}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || (importPath != "fmt" && importPath != "os") {
			continue
		}
		name := path.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		importNames[importPath] = name
	}
	count := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 || !isFmtPrintCall(call.Fun, importNames["fmt"]) || !isOSStderr(call.Args[0], importNames["os"]) {
			return true
		}
		for _, argument := range call.Args[1:] {
			literal, ok := argument.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				count++
				break
			}
		}
		return true
	})
	return count
}

func isFmtPrintCall(expression ast.Expr, importName string) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || (selector.Sel.Name != "Fprint" && selector.Sel.Name != "Fprintf" && selector.Sel.Name != "Fprintln") {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	return ok && importName != "" && identifier.Name == importName
}

func isOSStderr(expression ast.Expr, importName string) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Stderr" {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	return ok && importName != "" && identifier.Name == importName
}
