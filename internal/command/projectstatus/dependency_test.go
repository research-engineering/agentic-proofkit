package projectstatus

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
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
		for _, imported := range parsed.Imports {
			path := strings.Trim(imported.Path.Value, "\"")
			for _, forbidden := range []string{
				"internal/command/requirementbinding",
				"internal/command/requirementsourceadmission",
				"internal/command/testevidenceinventory",
			} {
				if strings.HasSuffix(path, forbidden) {
					t.Fatalf("%s imports child semantic owner %s directly", entry, path)
				}
			}
		}
	}
}

func TestProjectStatusProductionTopologyForbidsRepositoryMutationCalls(t *testing.T) {
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
	for _, entry := range mustProductionGoFiles(t) {
		content, err := os.ReadFile(entry)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), entry, content, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		aliases := map[string]string{}
		for _, imported := range parsed.Imports {
			importPath := strings.Trim(imported.Path.Value, "\"")
			if _, tracked := forbiddenCalls[importPath]; !tracked {
				continue
			}
			alias := path.Base(importPath)
			if imported.Name != nil {
				alias = imported.Name.Name
				if alias == "." || alias == "_" {
					t.Fatalf("%s uses unsupported import alias %q for %s", entry, alias, importPath)
				}
			}
			aliases[alias] = importPath
		}
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
				t.Errorf("%s calls repository mutation primitive %s.%s", entry, owner.Name, selector.Sel.Name)
			}
			return true
		})
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
