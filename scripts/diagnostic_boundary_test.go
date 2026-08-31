package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestToolDiagnosticBoundaryRejectsDirectDynamicStderrWrites(t *testing.T) {
	repositoryRoot := sourceHygieneRepoRoot(t)
	for _, scope := range []string{"cmd/agentic-proofkit", "internal/tools", "scripts"} {
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
		{name: "direct child stderr", source: `package main; import ("os"; "os/exec"); func main(){ command := exec.Command("tool"); command.Stderr = os.Stderr }`, want: 1},
		{name: "nested direct child stderr", source: `package main; import ("io"; "os"; "os/exec"); func main(){ command := exec.Command("tool"); command.Stderr = io.MultiWriter(os.Stderr) }`, want: 1},
		{name: "composite child stderr", source: `package main; import ("os"; "os/exec"); var command = exec.Cmd{Stderr: os.Stderr}`, want: 1},
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

func TestBrowserProofWriterRedactsInvalidResolution(t *testing.T) {
	repositoryRoot := sourceHygieneRepoRoot(t)
	secret := strings.Join([]string{"api", "_key=", "abc123456789"}, "")
	command := exec.Command("node", filepath.Join(repositoryRoot, "scripts", "write-browser-proof.mjs"))
	command.Dir = repositoryRoot
	command.Env = append(os.Environ(), "PROOFKIT_BROWSER_INPUT_RESOLUTION="+secret)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err == nil {
		t.Fatal("browser proof writer accepted invalid input resolution")
	}
	if stdout.Len() != 0 || stderr.String() != "<redacted-diagnostic-value>\n" || strings.Contains(stderr.String(), "abc123456789") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
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
		if assignment, ok := node.(*ast.AssignStmt); ok {
			for index, left := range assignment.Lhs {
				if index < len(assignment.Rhs) && isStderrField(left) && containsOSStderr(assignment.Rhs[index], importNames["os"]) {
					count++
				}
			}
		}
		if field, ok := node.(*ast.KeyValueExpr); ok {
			identifier, keyOK := field.Key.(*ast.Ident)
			if keyOK && identifier.Name == "Stderr" && containsOSStderr(field.Value, importNames["os"]) {
				count++
			}
		}
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

func isStderrField(expression ast.Expr) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Stderr"
}

func containsOSStderr(expression ast.Expr, importName string) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		candidate, ok := node.(ast.Expr)
		if ok && isOSStderr(candidate, importName) {
			found = true
			return false
		}
		return true
	})
	return found
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
