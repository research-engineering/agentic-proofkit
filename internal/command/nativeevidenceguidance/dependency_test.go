package nativeevidenceguidance_test

import (
	"go/parser"
	"go/token"
	"os"
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
			if isAmbientImport(imported.Path.Value) {
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

func isAmbientImport(quotedPath string) bool {
	for _, forbidden := range []string{
		"\"os\"", "\"os/exec\"", "\"path/filepath\"", "\"io/fs\"", "\"net\"", "\"net/http\"", "\"time\"", "\"math/rand\"", "\"crypto/rand\"", "\"runtime\"", "\"syscall\"",
	} {
		if quotedPath == forbidden {
			return true
		}
	}
	return false
}
