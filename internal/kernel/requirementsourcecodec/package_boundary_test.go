package requirementsourcecodec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestProductionPackageHasOneCodecAndNoSyntaxDependency(t *testing.T) {
	record := readCodecSelection(t)
	allowedOwners := map[string]struct{}{
		"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel": {},
		"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy":          {},
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	exported := []string{}
	productionFiles := []string{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		productionFiles = append(productionFiles, filepath.Base(path))
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range parsed.Imports {
			pathValue, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(pathValue, "github.com/research-engineering/agentic-proofkit/") {
				if _, exists := allowedOwners[pathValue]; !exists {
					t.Fatalf("codec imports an unapproved in-repository owner %q", pathValue)
				}
			}
			lower := strings.ToLower(pathValue)
			if strings.Contains(lower, "yaml") || strings.Contains(lower, "toml") {
				t.Fatalf("codec imports losing syntax dependency %q", pathValue)
			}
		}
		for _, declaration := range parsed.Decls {
			switch value := declaration.(type) {
			case *ast.FuncDecl:
				if value.Recv == nil && ast.IsExported(value.Name.Name) {
					exported = append(exported, "func:"+value.Name.Name)
				}
			case *ast.GenDecl:
				for _, specification := range value.Specs {
					switch item := specification.(type) {
					case *ast.TypeSpec:
						if ast.IsExported(item.Name.Name) {
							exported = append(exported, "type:"+item.Name.Name)
						}
					case *ast.ValueSpec:
						for _, name := range item.Names {
							if ast.IsExported(name.Name) {
								exported = append(exported, "value:"+name.Name)
							}
						}
					}
				}
			}
		}
	}
	wantFiles := record.GrammarOwner.ProductionFiles
	if !reflect.DeepEqual(productionFiles, wantFiles) {
		t.Fatalf("production codec files = %v, want exact single-grammar surface %v", productionFiles, wantFiles)
	}
	sort.Strings(exported)
	want := []string{
		"func:DefaultLimits", "func:ErrorCode", "func:Format", "func:FormatWithLimits",
		"func:MaxCanonicalBytes", "func:MaxLexicalTokens", "func:Parse", "func:ParseWithLimits",
		"type:ByteSpan", "type:Diagnostic", "type:Error", "type:Limits", "type:Location",
		"type:Position", "type:Result", "type:SourceMap", "value:DocumentKind", "value:SchemaVersion",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(exported, want) {
		t.Fatalf("exported codec surface = %v, want %v", exported, want)
	}
}

func TestSelectedV2GrammarOwnerRecordIsExact(t *testing.T) {
	owner := readCodecSelection(t).GrammarOwner
	wantFiles := []string{"diagnostic_path.go", "document.go", "format.go", "json_index.go", "limits.go", "parse.go", "shape.go", "types.go"}
	if owner.OwnerPackage != "internal/kernel/requirementsourcecodec" || owner.DocumentKind != DocumentKind || owner.SchemaVersion != SchemaVersion || !reflect.DeepEqual(owner.ProductionFiles, wantFiles) {
		t.Fatalf("grammar owner = %#v, want package identity and exact production inventory %v", owner, wantFiles)
	}
	if !sort.StringsAreSorted(owner.ProductionFiles) {
		t.Fatalf("grammar owner production files are not sorted: %v", owner.ProductionFiles)
	}
	packagePath, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	repositoryRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(repositoryRoot, packagePath)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.ToSlash(relative) != owner.OwnerPackage {
		t.Fatalf("grammar owner package = %q, actual package = %q", owner.OwnerPackage, filepath.ToSlash(relative))
	}
}
