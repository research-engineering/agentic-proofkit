package changeworkflowplan

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
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
		// Parsed imports cover every exec alias; Command( also matched DisplayCommand(.
		assertNoImports(t, production, "os/exec")
		assertNoSourceTokens(t, production, "Getenv(", "LookupEnv(", "Environ(")
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
		imports, err := sourceImports(entry.Name(), content)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, sourceUnit{name: filepath.Base(entry.Name()), imports: imports, text: string(content)})
	}
	return result
}

func sourceImports(name string, content []byte) (map[string]struct{}, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), name, content, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	imports := map[string]struct{}{}
	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return nil, err
		}
		imports[path] = struct{}{}
	}
	return imports, nil
}

func TestWorkflowProcessImportGuard(t *testing.T) {
	for _, alias := range []string{"", "process ", ". ", "_ "} {
		for _, literal := range []string{"\"os/exec\"", "`os/exec`"} {
			imports, err := sourceImports("fixture.go", []byte("package fixture\nimport "+alias+literal+"\n"))
			if err != nil {
				t.Fatal(err)
			}
			if _, forbidden := imports["os/exec"]; !forbidden {
				t.Fatalf("direct process authority escaped parsed-import policy: %s%s", alias, literal)
			}
		}
	}
	imports, err := sourceImports("fixture.go", []byte("package fixture\nfunc render(renderer Renderer) string { return renderer.DisplayCommand() }\n"))
	if err != nil || len(imports) != 0 {
		t.Fatal("pure rendering acquired process authority")
	}
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
