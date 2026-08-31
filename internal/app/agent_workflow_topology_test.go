package app

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestAgentWorkflowSemanticOwnerTopology(t *testing.T) {
	expectedCommands := []string{"change-workflow-plan", "native-evidence-guidance"}
	actualCommands := []string{}
	for _, descriptor := range commandDescriptors {
		if descriptor.runner != commandRunnerAgentWorkflow {
			continue
		}
		actualCommands = append(actualCommands, descriptor.name)
		switch descriptor.name {
		case "change-workflow-plan":
			if descriptor.input != commandInputRequired || !slices.Equal(descriptor.semanticOwnerDirs, []string{"changeworkflowplan"}) {
				t.Fatalf("planner carrier topology is invalid: %#v", descriptor)
			}
		case "native-evidence-guidance":
			if descriptor.input != commandInputNone || !slices.Equal(descriptor.semanticOwnerDirs, []string{"nativeevidenceguidance"}) {
				t.Fatalf("guidance carrier topology is invalid: %#v", descriptor)
			}
		default:
			t.Fatalf("agent workflow runner has surplus carrier %s", descriptor.name)
		}
	}
	sort.Strings(actualCommands)
	if !slices.Equal(actualCommands, expectedCommands) {
		t.Fatalf("agent workflow carriers=%v want %v", actualCommands, expectedCommands)
	}

	familyCount := 0
	for _, family := range generatedCommandFamilyCatalog().Families {
		if family.ID != "agent-workflow-planning" {
			continue
		}
		familyCount++
		if !slices.Equal(family.Commands, expectedCommands) {
			t.Fatalf("agent workflow family carriers=%v want %v", family.Commands, expectedCommands)
		}
	}
	if familyCount != 1 {
		t.Fatalf("agent workflow family count=%d want 1", familyCount)
	}

	root := repoRoot(t)
	assertSingleSemanticTableOwner(t, filepath.Join(root, "internal/command/changeworkflowplan"), "workflowCatalog", "catalog.go")
	assertSingleSemanticTableOwner(t, filepath.Join(root, "internal/command/nativeevidenceguidance"), "guidanceTable", "guidance.go")
	for _, retiredOwner := range []struct {
		dir  string
		name string
	}{
		{filepath.Join(root, "internal/command/changeworkflowplan"), "stageTable"},
		{filepath.Join(root, "internal/command/changeworkflowplan"), "promptProfiles"},
	} {
		if files := topLevelVariableOwners(t, retiredOwner.dir, retiredOwner.name); len(files) != 0 {
			t.Fatalf("retired semantic owner %s remains in %v", retiredOwner.name, files)
		}
	}
	assertNoRuntimeGuidanceResources(t, filepath.Join(root, "internal/command/changeworkflowplan"))
	assertNoRuntimeGuidanceResources(t, filepath.Join(root, "internal/command/nativeevidenceguidance"))
}

func assertSingleSemanticTableOwner(t *testing.T, dir, variable, expectedFile string) {
	t.Helper()
	files := topLevelVariableOwners(t, dir, variable)
	if !slices.Equal(files, []string{expectedFile}) {
		t.Fatalf("semantic owner %s files=%v want [%s]", variable, files, expectedFile)
	}
}

func topLevelVariableOwners(t *testing.T, dir, variable string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	owners := []string{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, declaration := range parsed.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.VAR {
				continue
			}
			for _, specification := range general.Specs {
				value := specification.(*ast.ValueSpec)
				for _, name := range value.Names {
					if name.Name == variable {
						owners = append(owners, entry.Name())
					}
				}
			}
		}
	}
	sort.Strings(owners)
	return owners
}

func assertNoRuntimeGuidanceResources(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) == ".go" {
			return nil
		}
		return fmt.Errorf("agent workflow owner contains runtime resource %s", path)
	})
	if err != nil {
		t.Fatal(err)
	}
}
