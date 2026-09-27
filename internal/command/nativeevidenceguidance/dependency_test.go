package nativeevidenceguidance_test

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func assertGuidanceProductionImports(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	productionFiles := 0
	for _, entry := range entries {
		path := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		productionFiles++
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imported := range parsed.Imports {
			ambient, err := isAmbientImport(imported.Path.Value)
			if err != nil {
				t.Fatalf("decode import in %s: %v", path, err)
			}
			if ambient {
				t.Fatalf("production import %s in %s is ambient", imported.Path.Value, path)
			}
		}
	}
	if productionFiles == 0 {
		t.Fatal("native evidence guidance has no production files")
	}
}

func TestGuidanceNoAmbientDependencyPredicates(t *testing.T) {
	t.Run("no_ambient_dependencies", func(t *testing.T) {
		assertGuidanceProductionImports(t)
	})
}

func isAmbientImport(quotedPath string) (bool, error) {
	importPath, err := strconv.Unquote(quotedPath)
	if err != nil {
		return false, err
	}
	for _, forbidden := range []string{
		"os", "os/exec", "path/filepath", "io/fs", "net", "net/http", "time", "math/rand", "crypto/rand", "runtime", "syscall",
	} {
		if importPath == forbidden {
			return true, nil
		}
	}
	return false, nil
}

func TestGuidanceAmbientImportLiteralControls(t *testing.T) {
	for _, fixture := range []struct {
		path    string
		ambient bool
	}{
		{"os", true}, {"os/exec", true}, {"path/filepath", true}, {"io/fs", true},
		{"net", true}, {"net/http", true}, {"time", true}, {"math/rand", true},
		{"crypto/rand", true}, {"runtime", true}, {"syscall", true},
		{"strings", false}, {"example.test/os", false}, {"net/http/httptest", false},
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
					got, err := isAmbientImport(parsed.Imports[0].Path.Value)
					if err != nil || got != fixture.ambient {
						t.Fatalf("literal %s: ambient=%t, err=%v; want %t", literal.value, got, err, fixture.ambient)
					}
				})
			}
		}
	}

	t.Run("invalid_literal_fails_closed", func(t *testing.T) {
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), "fixture.go", "package fixture\nimport \"os\\q\"\n", parser.ImportsOnly)
		if parseErr == nil || parsed == nil || len(parsed.Imports) != 1 {
			t.Fatalf("expected a rejected literal retained in the parser AST: %v", parseErr)
		}
		if _, err := isAmbientImport(parsed.Imports[0].Path.Value); err == nil {
			t.Fatal("invalid import literal was admitted")
		}
	})
}
