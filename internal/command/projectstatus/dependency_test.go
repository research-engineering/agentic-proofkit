package projectstatus

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
)

func TestProjectStatusDelegatesChildAdmissionToMaterializationOwner(t *testing.T) {
	for _, entry := range mustProductionGoFiles(t) {
		content, err := os.ReadFile(entry)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), entry, content, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		if err := projectStatusChildAdmissionImportError(parsed); err != nil {
			t.Fatalf("%s %v", entry, err)
		}
	}
}

func projectStatusChildAdmissionImportError(parsed *ast.File) error {
	for _, imported := range parsed.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return fmt.Errorf("decode import %s: %w", imported.Path.Value, err)
		}
		for _, forbidden := range []string{
			"internal/command/requirementbinding",
			"internal/command/requirementsourceadmission",
			"internal/command/testevidenceinventory",
		} {
			if strings.HasSuffix(importPath, forbidden) {
				return fmt.Errorf("imports child semantic owner %s directly", importPath)
			}
		}
	}
	return nil
}

func TestProjectStatusProductionTopologyForbidsRepositoryMutationCalls(t *testing.T) {
	for _, entry := range mustProductionGoFiles(t) {
		content, err := os.ReadFile(entry)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), entry, content, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		violations, err := projectStatusRepositoryMutationViolations(parsed)
		if err != nil {
			t.Fatalf("%s %v", entry, err)
		}
		for _, violation := range violations {
			t.Errorf("%s calls repository mutation primitive %s", entry, violation)
		}
	}
}

func projectStatusRepositoryMutationViolations(parsed *ast.File) ([]string, error) {
	forbiddenCalls := map[string]map[string]struct{}{
		"os": {
			"Chmod": {}, "Chown": {}, "Create": {}, "CreateTemp": {}, "Chtimes": {}, "Lchown": {}, "Link": {},
			"Mkdir": {}, "MkdirAll": {}, "MkdirTemp": {}, "OpenFile": {}, "Remove": {}, "RemoveAll": {}, "Rename": {},
			"Symlink": {}, "Truncate": {}, "WriteFile": {},
		},
		"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction": {
			"Apply": {}, "Recover": {},
		},
	}
	aliases := map[string]string{}
	for _, imported := range parsed.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return nil, fmt.Errorf("decode import %s: %w", imported.Path.Value, err)
		}
		if _, tracked := forbiddenCalls[importPath]; !tracked {
			continue
		}
		alias := path.Base(importPath)
		if imported.Name != nil {
			alias = imported.Name.Name
			if alias == "." || alias == "_" {
				return nil, fmt.Errorf("uses unsupported import alias %q for %s", alias, importPath)
			}
		}
		aliases[alias] = importPath
	}
	var violations []string
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		owner, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		importPath, tracked := aliases[owner.Name]
		if !tracked {
			return true
		}
		if _, forbidden := forbiddenCalls[importPath][selector.Sel.Name]; forbidden {
			violations = append(violations, owner.Name+"."+selector.Sel.Name)
		}
		return true
	})
	return violations, nil
}

func TestProjectStatusChildAdmissionImportLiteralControls(t *testing.T) {
	for _, fixture := range []struct {
		path      string
		forbidden bool
	}{
		{"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding", true},
		{"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission", true},
		{"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory", true},
		{"github.com/research-engineering/agentic-proofkit/internal/command/projectmaterialize", false},
		{"example.test/requirementbinding", false},
		{"example.test/internal/command/requirementbinding/child", false},
	} {
		for _, literal := range []struct{ name, value string }{
			{"quoted", strconv.Quote(fixture.path)},
			{"raw", "`" + fixture.path + "`"},
			{"escaped", fmt.Sprintf("\"%s\\x%02x\"", fixture.path[:len(fixture.path)-1], fixture.path[len(fixture.path)-1])},
		} {
			for _, alias := range []string{"", "named", ".", "_"} {
				t.Run(fixture.path+"/"+literal.name+"/alias="+alias, func(t *testing.T) {
					parsed, err := parser.ParseFile(token.NewFileSet(), "fixture.go", "package fixture\nimport "+alias+" "+literal.value+"\n", parser.ImportsOnly)
					if err != nil {
						t.Fatal(err)
					}
					err = projectStatusChildAdmissionImportError(parsed)
					if fixture.forbidden {
						want := "imports child semantic owner " + fixture.path + " directly"
						if err == nil || err.Error() != want {
							t.Fatalf("got %v; want %s", err, want)
						}
					} else if err != nil {
						t.Fatalf("allowed import rejected: %v", err)
					}
				})
			}
		}
	}
}

func TestProjectStatusMutationImportLiteralControls(t *testing.T) {
	for _, fixture := range []struct {
		path      string
		tracked   bool
		forbidden []string
		allowed   []string
	}{
		{"os", true, []string{"Chmod", "Chown", "Create", "CreateTemp", "Chtimes", "Lchown", "Link", "Mkdir", "MkdirAll", "MkdirTemp", "OpenFile", "Remove", "RemoveAll", "Rename", "Symlink", "Truncate", "WriteFile"}, []string{"ReadFile", "Stat", "Apply"}},
		{"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction", true, []string{"Apply", "Recover"}, []string{"WriteFile"}},
		{"example.test/os", false, nil, []string{"WriteFile", "Apply", "Recover"}},
	} {
		for _, literal := range []struct{ name, value string }{
			{"quoted", strconv.Quote(fixture.path)},
			{"raw", "`" + fixture.path + "`"},
			{"escaped", fmt.Sprintf("\"%s\\x%02x\"", fixture.path[:len(fixture.path)-1], fixture.path[len(fixture.path)-1])},
		} {
			for _, alias := range []string{"", "named", ".", "_"} {
				t.Run(fixture.path+"/"+literal.name+"/alias="+alias, func(t *testing.T) {
					owner := alias
					if owner == "" {
						owner = path.Base(fixture.path)
					}
					// Empty bodies isolate alias policy from mutation-call detection.
					calls := []string{""}
					if alias != "." && alias != "_" {
						calls = append(append(calls, fixture.allowed...), fixture.forbidden...)
					}
					for _, call := range calls {
						t.Run("call="+call, func(t *testing.T) {
							body := ""
							if call != "" && alias != "." && alias != "_" {
								body = owner + "." + call + "()"
							}
							parsed, err := parser.ParseFile(token.NewFileSet(), "fixture.go", "package fixture\nimport "+alias+" "+literal.value+"\nfunc f() { "+body+" }\n", parser.SkipObjectResolution)
							if err != nil {
								t.Fatal(err)
							}
							violations, err := projectStatusRepositoryMutationViolations(parsed)
							if fixture.tracked && (alias == "." || alias == "_") {
								want := fmt.Sprintf("uses unsupported import alias %q for %s", alias, fixture.path)
								if err == nil || err.Error() != want {
									t.Fatalf("got %v; want %s", err, want)
								}
								return
							}
							if err != nil {
								t.Fatal(err)
							}
							wantForbidden := false
							for _, forbidden := range fixture.forbidden {
								wantForbidden = wantForbidden || call == forbidden
							}
							if wantForbidden {
								if len(violations) != 1 || violations[0] != owner+"."+call {
									t.Fatalf("got %v; want only %s.%s", violations, owner, call)
								}
							} else if len(violations) != 0 {
								t.Fatalf("allowed source rejected: %v", violations)
							}
						})
					}
				})
			}
		}
	}
}

func TestProjectStatusInvalidImportLiteralFailsClosed(t *testing.T) {
	parsed, parseErr := parser.ParseFile(token.NewFileSet(), "fixture.go", "package fixture\nimport \"os\\q\"\n", parser.ImportsOnly)
	if parseErr == nil || parsed == nil || len(parsed.Imports) != 1 {
		t.Fatalf("expected a rejected literal retained in the parser AST: %v", parseErr)
	}
	if err := projectStatusChildAdmissionImportError(parsed); err == nil {
		t.Error("child admission guard admitted invalid import literal")
	}
	if _, err := projectStatusRepositoryMutationViolations(parsed); err == nil {
		t.Error("repository mutation guard admitted invalid import literal")
	}
}

func mustProductionGoFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	files := []string{}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
			files = append(files, entry.Name())
		}
	}
	if len(files) == 0 {
		t.Fatal("project status package has no production files")
	}
	return files
}
