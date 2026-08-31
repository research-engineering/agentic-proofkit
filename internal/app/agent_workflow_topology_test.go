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
	"strconv"
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
	assertWorkflowVocabularyOwnedByCatalog(t, filepath.Join(root, "internal/command/changeworkflowplan"))
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
	assertAgentWorkflowCarrierClosure(t, root)
}

func assertWorkflowVocabularyOwnedByCatalog(t *testing.T, dir string) {
	t.Helper()
	catalogPath := filepath.Join(dir, "catalog.go")
	catalog, err := parser.ParseFile(token.NewFileSet(), catalogPath, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", catalogPath, err)
	}
	vocabulary := map[string]struct{}{}
	ast.Inspect(catalog, func(node ast.Node) bool {
		literal := (*ast.BasicLit)(nil)
		switch value := node.(type) {
		case *ast.ValueSpec:
			if len(value.Names) == 1 && value.Names[0].Name == "workflowProfileID" && len(value.Values) == 1 {
				literal, _ = value.Values[0].(*ast.BasicLit)
			}
		case *ast.KeyValueExpr:
			switch key := value.Key.(type) {
			case *ast.Ident:
				if key.Name == "ID" || key.Name == "FirstAction" || key.Name == "State" || key.Name == "Action" {
					literal, _ = value.Value.(*ast.BasicLit)
				}
			case *ast.BasicLit:
				literal = key
			}
		}
		if literal == nil || literal.Kind != token.STRING {
			return true
		}
		decoded, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatalf("decode catalog literal: %v", err)
		}
		vocabulary[decoded] = struct{}{}
		return true
	})
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "catalog.go" || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatalf("decode workflow literal in %s: %v", path, err)
			}
			if _, duplicate := vocabulary[value]; duplicate {
				t.Fatalf("%s duplicates workflow catalog semantic literal %q", entry.Name(), value)
			}
			return true
		})
	}
}

func assertAgentWorkflowCarrierClosure(t *testing.T, root string) {
	t.Helper()
	closures := []struct {
		file            string
		imports         []string
		requiredCallees []string
	}{
		{
			file:            "agent_workflow_args.go",
			imports:         []string{"fmt", "github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"},
			requiredCallees: []string{"jsonpointer.Parse"},
		},
		{
			file: "agent_workflow_command.go",
			imports: []string{
				"github.com/research-engineering/agentic-proofkit/internal/command/changeworkflowplan",
				"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer",
				"io",
			},
			requiredCallees: []string{
				"append", "changeWorkflowTerminalText", "changeworkflowplan.Build", "changeworkflowplan.BuildAgentEnvelope",
				"changeworkflowplan.BuildTextProjection", "jsonpointer.SelectParsed", "len", "make", "newTerminalText",
				"parseAgentWorkflowArgs", "readInput", "renderTerminalText", "runNativeEvidenceGuidance", "writeDiagnostic",
				"writeDiagnosticf", "writeJSON", "writeText",
			},
		},
		{
			file:    "native_evidence_guidance_command.go",
			imports: []string{"github.com/research-engineering/agentic-proofkit/internal/command/nativeevidenceguidance", "io"},
			requiredCallees: []string{
				"append", "guidance.JSONValue", "len", "make", "nativeEvidenceGuidanceTerminalText", "nativeevidenceguidance.Build",
				"nativeevidenceguidance.TextProjection", "newTerminalText", "renderTerminalText", "writeJSON", "writeText",
			},
		},
		{
			file:            "terminal_style.go",
			imports:         []string{"fmt", "strings"},
			requiredCallees: []string{"terminalTokenStyle"},
		},
	}
	for _, closure := range closures {
		path := filepath.Join(root, "internal/app", closure.file)
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		imports := make([]string, 0, len(parsed.Imports))
		for _, specification := range parsed.Imports {
			value, err := strconv.Unquote(specification.Path.Value)
			if err != nil {
				t.Fatalf("decode import in %s: %v", path, err)
			}
			imports = append(imports, value)
		}
		sort.Strings(imports)
		expectedImports := append([]string(nil), closure.imports...)
		sort.Strings(expectedImports)
		if !slices.Equal(imports, expectedImports) {
			t.Fatalf("agent workflow carrier imports in %s=%v want %v", closure.file, imports, expectedImports)
		}

		calleeSet := map[string]struct{}{}
		explicitReadInputCalls := 0
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := ""
			switch function := call.Fun.(type) {
			case *ast.Ident:
				callee = function.Name
				if function.Name == "readInput" {
					explicitReadInputCalls++
					if len(call.Args) != 2 {
						t.Fatalf("agent workflow carrier %s must pass path and stdin to readInput", closure.file)
					}
					path, pathOK := call.Args[0].(*ast.SelectorExpr)
					if !pathOK {
						t.Fatalf("agent workflow carrier %s must pass options.inputPath to readInput", closure.file)
					}
					owner, ownerOK := path.X.(*ast.Ident)
					stdin, stdinOK := call.Args[1].(*ast.Ident)
					if !ownerOK || owner.Name != "options" || path.Sel.Name != "inputPath" || !stdinOK || stdin.Name != "stdin" {
						t.Fatalf("agent workflow carrier %s must read only options.inputPath through the supplied stdin", closure.file)
					}
				}
			case *ast.SelectorExpr:
				owner, ok := function.X.(*ast.Ident)
				if !ok {
					t.Fatalf("agent workflow carrier %s contains a nonlocal selector call", closure.file)
				}
				callee = owner.Name + "." + function.Sel.Name
			case *ast.ArrayType:
				return true
			default:
				t.Fatalf("agent workflow carrier %s contains an indirect call of type %T", closure.file, call.Fun)
			}
			calleeSet[callee] = struct{}{}
			return true
		})
		if closure.file == "agent_workflow_command.go" && explicitReadInputCalls != 1 {
			t.Fatalf("agent workflow carrier explicit readInput calls=%d want 1", explicitReadInputCalls)
		}
		for _, required := range closure.requiredCallees {
			if _, ok := calleeSet[required]; !ok {
				t.Fatalf("agent workflow carrier %s is missing required owner call %s", closure.file, required)
			}
		}
	}
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
