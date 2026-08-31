package changeworkflowplan

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkflowAmbientAuthorityPredicates(t *testing.T) {
	production := productionSource(t)
	t.Run("bounded_transport_only", func(t *testing.T) {
		if _, err := Build(initialInput()); err != nil {
			t.Fatalf("explicit bounded input was rejected: %v", err)
		}
	})
	t.Run("forbidden_fields", func(t *testing.T) {
		for _, field := range []string{"repositoryRoot", "prompt", "maxContext", "command", "environment", "receipt", "authority"} {
			input := initialInput()
			input[field] = "caller-value"
			requireReject(t, input)
		}
	})
	t.Run("no_clock_random_network", func(t *testing.T) {
		assertNoImports(t, production, "time", "math/rand", "crypto/rand", "net", "net/http")
	})
	t.Run("no_filesystem_git", func(t *testing.T) {
		assertNoImports(t, production, "io/fs", "os", "path/filepath")
		assertNoSourceTokens(t, production, "git.Command", "go-git")
	})
	t.Run("no_process_environment", func(t *testing.T) {
		assertNoImports(t, production, "os/exec")
		assertNoSourceTokens(t, production, "Getenv(", "LookupEnv(", "Environ(", "Command(")
	})
	t.Run("no_setup_or_route", func(t *testing.T) {
		assertNoSourceTokens(t, production, "agentroute", "setup facade", "repository scan", "consumer-specific")
	})
}

type sourceUnit struct {
	name    string
	imports map[string]struct{}
	text    string
}

func productionSource(t *testing.T) []sourceUnit {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	result := []sourceUnit{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		content, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), entry.Name(), content, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		imports := map[string]struct{}{}
		for _, imported := range parsed.Imports {
			imports[strings.Trim(imported.Path.Value, "\"")] = struct{}{}
		}
		result = append(result, sourceUnit{name: filepath.Base(entry.Name()), imports: imports, text: string(content)})
	}
	return result
}

func assertNoImports(t *testing.T, units []sourceUnit, forbidden ...string) {
	t.Helper()
	for _, unit := range units {
		for _, imported := range forbidden {
			if _, exists := unit.imports[imported]; exists {
				t.Fatalf("%s imports forbidden package %s", unit.name, imported)
			}
		}
	}
}

func assertNoSourceTokens(t *testing.T, units []sourceUnit, forbidden ...string) {
	t.Helper()
	for _, unit := range units {
		for _, tokenValue := range forbidden {
			if strings.Contains(unit.text, tokenValue) {
				t.Fatalf("%s contains forbidden production token %q", unit.name, tokenValue)
			}
		}
	}
}
