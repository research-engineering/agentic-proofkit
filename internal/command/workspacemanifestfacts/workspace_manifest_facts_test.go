package workspacemanifestfacts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/workspaceplanning"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildProjectsManifestFactsAndPlanningInputs(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.045131377523903059328620085892776244655592414046718681948892749746792823542716")
	output, exitCode, err := Build(validInput(t))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Build() exitCode=%d output=%#v", exitCode, output)
	}
	if output["state"] != "passed" {
		t.Fatalf("state=%v", output["state"])
	}
	if output["reportId"] != "proofkit.workspace.manifest_facts.fixture" {
		t.Fatalf("reportId=%v", output["reportId"])
	}
	if got := strings.Join(stringsOf(output["knownPackageNames"]), ","); got != "@scope/alpha,@scope/beta" {
		t.Fatalf("knownPackageNames=%s", got)
	}
	universe := output["packageUniverse"].(map[string]any)
	edges := universe["workspaceDependencyEdges"].([]any)
	if len(edges) != 2 {
		t.Fatalf("workspaceDependencyEdges=%#v, want 2", edges)
	}
	firstEdge := edges[0].(map[string]any)
	if firstEdge["fromKind"] != "package" || firstEdge["fromName"] != "@scope/alpha" || firstEdge["toName"] != "@scope/beta" {
		t.Fatalf("unexpected first edge: %#v", firstEdge)
	}
	changedPackages := output["changedPackagePlanPackages"].([]any)
	alpha := changedPackages[0].(map[string]any)
	if alpha["dirName"] != "alpha" || strings.Join(stringsOf(alpha["workspaceDependencies"]), ",") != "@scope/beta" {
		t.Fatalf("alpha planning facts=%#v", alpha)
	}
	packages := output["packages"].([]any)
	alphaFacts := packages[0].(map[string]any)
	if strings.Join(dependencyRefNames(alphaFacts["dependencyRefs"]), ",") != "@scope/beta,lodash" {
		t.Fatalf("alpha dependency refs=%#v", alphaFacts["dependencyRefs"])
	}
}

func TestBuildOutputsAreAdmittedByWorkspacePlanningCommands(t *testing.T) {
	output, _, err := Build(validInput(t))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	changedInput := map[string]any{
		"schemaVersion":            json.Number("1"),
		"changedPaths":             []any{"packages/alpha/src/index.ts"},
		"escalationRules":          []any{},
		"includeReverseDependents": true,
		"packagesRoot":             "packages",
		"packages":                 output["changedPackagePlanPackages"],
	}
	if _, err := workspaceplanning.BuildChangedPackagePlan(changedInput); err != nil {
		t.Fatalf("BuildChangedPackagePlan() rejected projected packages: %v", err)
	}
	shardInput := map[string]any{
		"schemaVersion": json.Number("1"),
		"packages":      output["shardPartitionPackages"],
		"roots":         []any{map[string]any{"name": "@scope/alpha", "workspaceDependencies": []any{"@scope/beta"}}},
		"shardTotal":    json.Number("2"),
	}
	if _, _, err := workspaceplanning.BuildShardPartition(shardInput); err != nil {
		t.Fatalf("BuildShardPartition() rejected projected packages: %v", err)
	}
}

func TestBuildRejectsUnsafeManifestPathAndDuplicatePackageIdentity(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.042789860620987407196887112869252006583828805316041850684999615267856780669343")
	t.Run("unsafe manifest path", func(t *testing.T) {
		input := validInput(t).(map[string]any)
		input["packages"].([]any)[0].(map[string]any)["manifestPath"] = "../package.json"
		_, _, err := Build(input)
		if err == nil || !strings.Contains(err.Error(), "escape") {
			t.Fatalf("Build() error=%v, want unsafe path failure", err)
		}
	})
	t.Run("duplicate package name", func(t *testing.T) {
		input := validInput(t).(map[string]any)
		input["packages"].([]any)[1].(map[string]any)["manifest"].(map[string]any)["name"] = "@scope/alpha"
		_, _, err := Build(input)
		if err == nil || !strings.Contains(err.Error(), "package name must be unique") {
			t.Fatalf("Build() error=%v, want duplicate package name failure", err)
		}
	})
	t.Run("duplicate package dir", func(t *testing.T) {
		input := validInput(t).(map[string]any)
		input["packages"].([]any)[1].(map[string]any)["dirName"] = "alpha"
		_, _, err := Build(input)
		if err == nil || !strings.Contains(err.Error(), "package dirName must be unique") {
			t.Fatalf("Build() error=%v, want duplicate package dir failure", err)
		}
	})
	t.Run("dirName rejected by planning owner surface", func(t *testing.T) {
		input := validInput(t).(map[string]any)
		input["packages"].([]any)[0].(map[string]any)["dirName"] = "bad dir"
		_, _, err := Build(input)
		if err == nil || !strings.Contains(err.Error(), "stable rule identifier") {
			t.Fatalf("Build() error=%v, want planning-compatible dirName failure", err)
		}
	})
}

func TestBuildRejectsUnknownManifestFieldsAndUnsortedDependencyFields(t *testing.T) {
	t.Run("unknown top-level discovery key", func(t *testing.T) {
		input := validInput(t).(map[string]any)
		input["repoRoot"] = "."
		_, _, err := Build(input)
		if err == nil || !strings.Contains(err.Error(), "unsupported field") {
			t.Fatalf("Build() error=%v, want unsupported discovery field failure", err)
		}
	})
	t.Run("unknown manifest field", func(t *testing.T) {
		input := validInput(t).(map[string]any)
		input["packages"].([]any)[0].(map[string]any)["manifest"].(map[string]any)["engines"] = map[string]any{"node": ">=20"}
		_, _, err := Build(input)
		if err == nil || !strings.Contains(err.Error(), "unsupported field") {
			t.Fatalf("Build() error=%v, want unsupported manifest field failure", err)
		}
	})
	t.Run("unsorted dependency fields", func(t *testing.T) {
		input := validInput(t).(map[string]any)
		input["dependencyFields"] = []any{"devDependencies", "dependencies"}
		_, _, err := Build(input)
		if err == nil || !strings.Contains(err.Error(), "sorted") {
			t.Fatalf("Build() error=%v, want dependencyFields ordering failure", err)
		}
	})
	t.Run("malformed dependency map", func(t *testing.T) {
		input := validInput(t).(map[string]any)
		input["packages"].([]any)[0].(map[string]any)["manifest"].(map[string]any)["dependencies"] = []any{"@scope/beta"}
		_, _, err := Build(input)
		if err == nil || !strings.Contains(err.Error(), "dependencies must be an object") {
			t.Fatalf("Build() error=%v, want malformed dependency map failure", err)
		}
	})
	t.Run("control character script", func(t *testing.T) {
		input := validInput(t).(map[string]any)
		scripts := input["packages"].([]any)[0].(map[string]any)["manifest"].(map[string]any)["scripts"].(map[string]any)
		scripts["test"] = "go test\n./packages/alpha"
		_, _, err := Build(input)
		if err == nil || !strings.Contains(err.Error(), "control characters") {
			t.Fatalf("Build() error=%v, want control character failure", err)
		}
	})
}

func TestBuildDoesNotDereferenceManifestPaths(t *testing.T) {
	input := validInput(t).(map[string]any)
	input["root"].(map[string]any)["manifestPath"] = "missing/package.json"
	if _, _, err := Build(input); err != nil {
		t.Fatalf("Build() with nonexistent manifestPath error = %v", err)
	}

	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(`{"name":"from-disk","scripts":{"test":"exit 1"}}`), 0o600); err != nil {
		t.Fatalf("write conflicting package.json: %v", err)
	}
	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("chdir temp: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previousDir); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	output, _, err := Build(validInput(t))
	if err != nil {
		t.Fatalf("Build() with conflicting cwd package.json error = %v", err)
	}
	root := output["root"].(map[string]any)
	if root["name"] != "root" {
		t.Fatalf("root name=%v, want inline manifest name", root["name"])
	}
}

func TestBuildOutputIsStableForReorderedPackagesAndMaps(t *testing.T) {
	left, _, err := Build(validInput(t))
	if err != nil {
		t.Fatalf("Build(left) error = %v", err)
	}
	input := validInput(t).(map[string]any)
	packages := input["packages"].([]any)
	input["packages"] = []any{packages[1], packages[0]}
	right, _, err := Build(input)
	if err != nil {
		t.Fatalf("Build(right) error = %v", err)
	}
	leftJSON, err := json.Marshal(left)
	if err != nil {
		t.Fatalf("marshal left: %v", err)
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		t.Fatalf("marshal right: %v", err)
	}
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("output must be stable for reordered packages\nleft=%s\nright=%s", leftJSON, rightJSON)
	}
}

func TestBuildDoesNotCreateWorkspaceEdgesForExternalDependencies(t *testing.T) {
	input := validInput(t).(map[string]any)
	alpha := input["packages"].([]any)[0].(map[string]any)["manifest"].(map[string]any)
	alpha["dependencies"] = map[string]any{"lodash": "^4.17.21"}
	output, _, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	universe := output["packageUniverse"].(map[string]any)
	edges := universe["workspaceDependencyEdges"].([]any)
	if len(edges) != 1 {
		t.Fatalf("workspaceDependencyEdges=%#v, want only root->beta edge", edges)
	}
}

func TestBuildPreservesDuplicateWorkspaceTargetsAcrossDependencyFields(t *testing.T) {
	input := validInput(t).(map[string]any)
	alpha := input["packages"].([]any)[0].(map[string]any)["manifest"].(map[string]any)
	alpha["devDependencies"] = map[string]any{"@scope/beta": "workspace:^"}
	output, _, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	universe := output["packageUniverse"].(map[string]any)
	edges := universe["workspaceDependencyEdges"].([]any)
	if len(edges) != 3 {
		t.Fatalf("workspaceDependencyEdges=%#v, want root edge plus two field-specific alpha edges", edges)
	}
	seenAlphaFields := map[string]string{}
	for _, raw := range edges {
		edge := raw.(map[string]any)
		if edge["fromName"] == "@scope/alpha" && edge["toName"] == "@scope/beta" {
			seenAlphaFields[edge["field"].(string)] = edge["version"].(string)
		}
	}
	if seenAlphaFields["dependencies"] != "workspace:*" || seenAlphaFields["devDependencies"] != "workspace:^" {
		t.Fatalf("field-specific alpha edges=%#v", seenAlphaFields)
	}
}

func validInput(t *testing.T) any {
	t.Helper()
	input, err := admission.DecodeJSON(strings.NewReader(`{
  "schemaVersion": 1,
  "projectionId": "proofkit.workspace.manifest_facts.fixture",
  "dependencyFields": ["dependencies", "devDependencies"],
  "root": {
    "manifestPath": "package.json",
    "manifest": {
      "name": "root",
      "scripts": {
        "check": "npm run go:check",
        "test": "go test ./..."
      },
      "dependencies": {
        "@scope/beta": "workspace:*"
      },
      "devDependencies": {}
    }
  },
  "packages": [
    {
      "manifestPath": "packages/alpha/package.json",
      "packageDir": "packages/alpha",
      "dirName": "alpha",
      "manifest": {
        "name": "@scope/alpha",
        "scripts": {
          "build": "go build ./...",
          "test": "go test ./packages/alpha"
        },
        "dependencies": {
          "@scope/beta": "workspace:*",
          "lodash": "^4.17.21"
        },
        "devDependencies": {}
      }
    },
    {
      "manifestPath": "packages/beta/package.json",
      "packageDir": "packages/beta",
      "dirName": "beta",
      "manifest": {
        "name": "@scope/beta",
        "scripts": {
          "test": "go test ./packages/beta"
        },
        "dependencies": {},
        "devDependencies": {}
      }
    }
  ],
  "nonClaims": ["Fixture manifests are caller-owned test data."]
}`), 1<<20)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return input
}

func stringsOf(raw any) []string {
	values := raw.([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.(string))
	}
	return result
}

func dependencyRefNames(raw any) []string {
	values := raw.([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.(map[string]any)["name"].(string))
	}
	return result
}
