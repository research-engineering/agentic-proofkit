package projectstatus

import (
	"go/parser"
	"go/token"
	"os"
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
