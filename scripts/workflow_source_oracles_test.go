package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestWorkflowsUseExplicitHostedRunnerLabels(t *testing.T) {
	for _, path := range workflowPathsForTest(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			workflow := readWorkflowForTest(t, path)
			for jobID, job := range workflow.Jobs {
				for _, label := range runnerLabels(job.RunsOn) {
					if strings.HasSuffix(label, "-latest") {
						t.Fatalf("%s job %q uses floating hosted runner label %q", path, jobID, label)
					}
				}
			}
		})
	}
}

func TestWorkflowClosedKeyAdmission(t *testing.T) {
	paths := workflowPathsForTest(t)
	actualPaths := make([]string, 0, len(paths))
	for _, path := range paths {
		relative := strings.TrimPrefix(filepath.ToSlash(path), "../")
		actualPaths = append(actualPaths, relative)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if err := validateWorkflowClosedKeys(path, raw); err != nil {
			t.Fatalf("owner workflow %s: %v", path, err)
		}
	}
	if !reflect.DeepEqual(actualPaths, admittedWorkflowPaths) {
		t.Fatalf("closed-key workflow inventory=%v, want exact %v", actualPaths, admittedWorkflowPaths)
	}

	ciPath := filepath.Join("..", ".github", "workflows", "ci.yml")
	ciRaw := readWorkflowBytesForTest(t, ciPath)
	for _, mutant := range []struct {
		name      string
		anchor    string
		insertion string
	}{
		{name: "workflow run-name", anchor: "name: ci\n", insertion: "run-name: shadow\n"},
		{name: "workflow unknown key", anchor: "name: ci\n", insertion: "proofkit-shadow: true\n"},
		{name: "workflow duplicate key", anchor: "name: ci\n", insertion: "name: shadow\n"},
		{name: "workflow merge key", anchor: "name: ci\n", insertion: "<<: {}\n"},
		{name: "jobs duplicate key", anchor: "  source-quality:\n", insertion: "    steps: []\n  source-quality:\n"},
		{name: "jobs merge key", anchor: "jobs:\n", insertion: "  <<: {}\n"},
		{name: "jobs non-string key", anchor: "jobs:\n", insertion: "  ? [shadow]\n  : {steps: []}\n"},
	} {
		t.Run(mutant.name, func(t *testing.T) {
			assertClosedWorkflowMutationRejected(t, ciPath, ciRaw, mutant.anchor, mutant.anchor+mutant.insertion)
		})
	}

	jobMutants := []struct {
		name      string
		insertion string
	}{
		{name: "container", insertion: "    container: attacker.example/proofkit-shadow:latest\n"},
		{name: "strategy", insertion: "    strategy:\n      fail-fast: false\n"},
		{name: "services", insertion: "    services: {}\n"},
		{name: "outputs", insertion: "    outputs: {}\n"},
		{name: "concurrency", insertion: "    concurrency: shadow\n"},
		{name: "environment", insertion: "    environment: shadow\n"},
		{name: "defaults", insertion: "    defaults:\n      run:\n        shell: bash\n"},
		{name: "continue-on-error", insertion: "    continue-on-error: false\n"},
		{name: "reusable uses", insertion: "    uses: ./.github/workflows/shadow.yml\n"},
		{name: "reusable with", insertion: "    with: {}\n"},
		{name: "reusable secrets", insertion: "    secrets: inherit\n"},
		{name: "duplicate", insertion: "    name: shadow\n"},
		{name: "merge", insertion: "    <<: {}\n"},
		{name: "unknown", insertion: "    proofkit-shadow: true\n"},
	}
	for _, job := range []struct {
		name   string
		anchor string
	}{
		{name: "producer", anchor: "  source-quality:\n"},
		{name: "aggregate", anchor: "  ci-required-gate:\n"},
	} {
		for _, mutant := range jobMutants {
			t.Run(job.name+" "+mutant.name, func(t *testing.T) {
				assertClosedWorkflowMutationRejected(
					t,
					ciPath,
					ciRaw,
					job.anchor,
					job.anchor+mutant.insertion,
				)
			})
		}
	}

	stepMutants := []struct {
		name      string
		insertion string
	}{
		{name: "continue-on-error", insertion: "        continue-on-error: false\n"},
		{name: "shell", insertion: "        shell: bash {0} || true\n"},
		{name: "timeout-minutes", insertion: "        timeout-minutes: 1\n"},
		{name: "working-directory", insertion: "        working-directory: shadow\n"},
		{name: "duplicate", insertion: "        name: shadow\n"},
		{name: "merge", insertion: "        <<: {}\n"},
		{name: "unknown", insertion: "        proofkit-shadow: true\n"},
	}
	for _, step := range []struct {
		name   string
		anchor string
	}{
		{name: "producer", anchor: "      - name: Checkout\n"},
		{name: "aggregate", anchor: "      - name: Verify required quality results\n"},
	} {
		for _, mutant := range stepMutants {
			t.Run(step.name+" step "+mutant.name, func(t *testing.T) {
				assertClosedWorkflowMutationRejected(
					t,
					ciPath,
					ciRaw,
					step.anchor,
					step.anchor+mutant.insertion,
				)
			})
		}
	}

	releasePath := filepath.Join("..", ".github", "workflows", "release.yml")
	releaseRaw := readWorkflowBytesForTest(t, releasePath)
	for _, mutant := range []struct {
		name        string
		old         string
		replacement string
	}{
		{
			name:        "environment on unowned job",
			old:         "  candidate:\n",
			replacement: "  candidate:\n    environment: shadow\n",
		},
		{
			name:        "publish environment wrong scalar",
			old:         "    environment: npm-production\n",
			replacement: "    environment: shadow\n",
		},
		{
			name:        "publish environment wrong kind",
			old:         "    environment: npm-production\n",
			replacement: "    environment:\n      name: npm-production\n",
		},
		{
			name:        "pypi environment wrong name",
			old:         "      name: pypi\n",
			replacement: "      name: shadow\n",
		},
		{
			name:        "pypi environment wrong url",
			old:         "      url: https://pypi.org/p/agentic-proofkit\n",
			replacement: "      url: https://example.invalid/shadow\n",
		},
		{
			name:        "pypi environment surplus",
			old:         "      url: https://pypi.org/p/agentic-proofkit\n",
			replacement: "      url: https://pypi.org/p/agentic-proofkit\n      proofkit-shadow: true\n",
		},
		{
			name:        "publish environment missing",
			old:         "    environment: npm-production\n",
			replacement: "",
		},
	} {
		t.Run(mutant.name, func(t *testing.T) {
			assertClosedWorkflowMutationRejected(t, releasePath, releaseRaw, mutant.old, mutant.replacement)
		})
	}
}

func readWorkflowBytesForTest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func assertClosedWorkflowMutationRejected(
	t *testing.T,
	path string,
	owner string,
	old string,
	replacement string,
) {
	t.Helper()
	mutated := strings.Replace(owner, old, replacement, 1)
	if mutated == owner {
		t.Fatalf("workflow mutation did not change %s", path)
	}
	if err := validateWorkflowClosedKeys(path, []byte(mutated)); err == nil {
		t.Fatalf("closed-key workflow oracle admitted mutation in %s", path)
	}
}

func workflowPathsForTest(t *testing.T) []string {
	t.Helper()
	patterns := []string{
		filepath.Join("..", ".github", "workflows", "*.yml"),
		filepath.Join("..", ".github", "workflows", "*.yaml"),
	}
	var paths []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob workflows with %s: %v", pattern, err)
		}
		paths = append(paths, matches...)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("no workflow files found")
	}
	return paths
}

func TestWorkflowExternalActionsUseFullCommitSHAs(t *testing.T) {
	if err := validateWorkflowActionPins(filepath.Join("..")); err != nil {
		t.Fatal(err)
	}
	base := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	for _, reference := range []string{"actions/checkout@v7", "actions/checkout@3d3c42e"} {
		t.Run(reference, func(t *testing.T) {
			workflow := cloneWorkflow(t, base)
			job := workflow.Jobs["source-quality"]
			job.Steps[0].Uses = reference
			workflow.Jobs["source-quality"] = job
			if err := validateWorkflowActionReferences(workflow); err == nil {
				t.Fatalf("unpinned action reference %q was admitted", reference)
			}
		})
	}
	for _, reference := range []string{
		"./scripts/shadow-action",
		"./.github/actions/../shadow-action",
		`.\\.github\\actions\\shadow-action`,
	} {
		t.Run(reference, func(t *testing.T) {
			if err := validateActionReference(reference); err == nil {
				t.Fatalf("escaping local action reference %q was admitted", reference)
			}
		})
	}
}

func TestRootCheckRetainsRequiredProofGates(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := validateRootCheckScript(manifest.Scripts["check"]); err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{"npm run go:check", "npm run browser:check", "npm run package:artifact"} {
		mutant := strings.Replace(manifest.Scripts["check"], " && "+removed, "", 1)
		if err := validateRootCheckScript(mutant); err == nil {
			t.Fatalf("check oracle admitted removal of %q", removed)
		}
	}
}

func validateRootCheckScript(script string) error {
	if script != "npm run npm:version && npm run source-hygiene && npm run command-contract:check && npm run command-family:check && npm run text-policy && npm run mermaid:check && npm run go:check && npm run browser:check && npm run package:artifact && npm run self:receipt && npm run self:coverage && npm run release:closeout" {
		return errors.New("root check must retain the exact ordered AND-only proof gates")
	}
	return nil
}

func TestGoDependencyGateWiring(t *testing.T) {
	scripts := readPackageScriptsForTest(t)
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err := validateGoDependencyGate(scripts, workflow); err != nil {
		t.Fatal(err)
	}
	for _, mutant := range []struct {
		name, key, value string
	}{
		{"missing tidy", "go:deps", "go mod verify"},
		{"missing verify", "go:deps", "go mod tidy -diff"},
		{"mutating tidy", "go:deps", "go mod tidy && go mod verify"},
		{"ignored tidy failure", "go:deps", "go mod tidy -diff; go mod verify"},
		{"ignored gate failure", "go:deps", scripts["go:deps"] + " || true"},
		{"text-only gate", "go:deps", "echo 'go mod tidy -diff && go mod verify'"},
		{"reversed dependency checks", "go:deps", "go mod verify && go mod tidy -diff"},
		{"missing local gate", "go:check", strings.Replace(scripts["go:check"], " && npm run go:deps", "", 1)},
		{"late local gate", "go:check", strings.Replace(scripts["go:check"], "npm run go:deps && npm run go:test", "npm run go:test && npm run go:deps", 1)},
		{"ignored local failure", "go:check", strings.Replace(scripts["go:check"], "npm run go:deps &&", "npm run go:deps;", 1)},
		{"missing root gate", "check", strings.Replace(scripts["check"], " && npm run go:check", "", 1)},
		{"masked root failure", "check", scripts["check"] + " && true || true"},
		{"root extra command", "check", scripts["check"] + " && true"},
		{"root semicolon", "check", strings.Replace(scripts["check"], " && ", "; ", 1)},
		{"root reorder", "check", strings.Replace(scripts["check"], "npm run npm:version && npm run source-hygiene", "npm run source-hygiene && npm run npm:version", 1)},
	} {
		t.Run(mutant.name, func(t *testing.T) {
			changed := maps.Clone(scripts)
			if changed[mutant.key] == mutant.value {
				t.Fatal("mutation did not change owner script")
			}
			changed[mutant.key] = mutant.value
			if err := validateGoDependencyGate(changed, workflow); err == nil {
				t.Fatal("dependency gate oracle admitted changed script")
			}
		})
	}
	// Independent keys cover the protected chains and upstream CI npm gates.
	for _, gate := range []string{
		"check", "npm:version", "source-hygiene", "command-contract:check",
		"command-family:check", "text-policy", "mermaid:check", "go:check",
		"browser:check", "package:artifact", "self:receipt", "self:coverage",
		"release:closeout", "go:fmt", "go:deps", "go:test", "go:vet",
		"go:staticcheck", "go:actionlint", "go:vulncheck", "browser:static-check",
	} {
		for _, prefix := range []string{"pre", "post"} {
			for _, value := range []struct{ name, body string }{
				{"empty", ""}, {"no-op", "true"}, {"mutating", "go mod tidy"},
			} {
				hook := prefix + gate
				t.Run("npm hooks/"+hook+"/"+value.name, func(t *testing.T) {
					changed := maps.Clone(scripts)
					changed[hook] = value.body
					if err := validateGoDependencyGate(changed, workflow); err == nil {
						t.Fatalf("dependency gate oracle admitted hook key %q", hook)
					}
				})
			}
		}
	}
	for _, key := range []string{"docs", "predocs", "postdocs", "precheck:extra", "prego:deps:extra"} {
		t.Run("unrelated script/"+key, func(t *testing.T) {
			changed := maps.Clone(scripts)
			changed[key] = "true"
			if err := validateGoDependencyGate(changed, workflow); err != nil {
				t.Fatalf("bounded dependency oracle claimed unrelated script %q: %v", key, err)
			}
		})
	}
	for _, mutation := range []string{"missing", "duplicate", "text only", "late", "condition", "continue on error"} {
		t.Run("CI "+mutation, func(t *testing.T) {
			changed := cloneWorkflow(t, workflow)
			job := changed.Jobs["source-quality"]
			index, err := uniqueStepIndex(job.Steps, "Verify Go dependency consistency")
			if err != nil || index < 0 {
				t.Fatalf("dependency step index=%d err=%v", index, err)
			}
			switch mutation {
			case "missing":
				job.Steps = append(job.Steps[:index], job.Steps[index+1:]...)
			case "duplicate":
				job.Steps = append(job.Steps, job.Steps[index])
			case "text only":
				job.Steps[index].Run = "echo 'npm run go:deps'"
			case "late":
				testIndex, err := uniqueStepIndex(job.Steps, "Run all Go tests")
				if err != nil || testIndex < 0 {
					t.Fatalf("Go test step index=%d err=%v", testIndex, err)
				}
				job.Steps[index], job.Steps[testIndex] = job.Steps[testIndex], job.Steps[index]
			case "condition":
				job.Steps[index].If = "${{ false }}"
				job.Steps[index].ifPresent = true
			case "continue on error":
				job.Steps[index].ContinueOnError = true
				job.Steps[index].continueOnErrorPresent = true
			}
			changed.Jobs["source-quality"] = job
			if err := validateGoDependencyGate(scripts, changed); err == nil {
				t.Fatal("dependency gate oracle admitted changed CI wiring")
			}
		})
	}
}

func readPackageScriptsForTest(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest.Scripts
}

func validateGoDependencyGate(scripts map[string]string, workflow githubWorkflow) error {
	if scripts["go:deps"] != "go mod tidy -diff && go mod verify" {
		return errors.New("go:deps must fail closed on non-mutating tidy and module verification")
	}
	if scripts["go:check"] != "npm run go:fmt && npm run go:deps && npm run go:test && npm run go:vet && npm run go:staticcheck && npm run go:actionlint && npm run go:vulncheck" {
		return errors.New("go:check must retain the exact ordered Go gates")
	}
	if err := validateRootCheckScript(scripts["check"]); err != nil {
		return err
	}
	if err := validateCIRequiredAggregate(workflow); err != nil {
		return err
	}
	// Project only the already-admitted exact chains and CI steps, not arbitrary shell.
	protected := []string{"check"}
	for _, chain := range []string{scripts["check"], scripts["go:check"]} {
		for _, command := range strings.Split(chain, " && ") {
			protected = append(protected, strings.TrimPrefix(command, "npm run "))
		}
	}
	for _, step := range workflow.Jobs["source-quality"].Steps {
		if gate, ok := strings.CutPrefix(step.Run, "npm run "); ok {
			protected = append(protected, gate)
		}
	}
	for _, gate := range protected {
		for _, prefix := range []string{"pre", "post"} {
			if _, exists := scripts[prefix+gate]; exists {
				return fmt.Errorf("protected npm gate %q must omit lifecycle hook key %q", gate, prefix+gate)
			}
		}
	}
	return nil
}

func TestGoDependencyGateFailurePropagation(t *testing.T) {
	scripts := readPackageScriptsForTest(t)
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	steps := workflow.Jobs["source-quality"].Steps
	index, err := uniqueStepIndex(steps, "Verify Go dependency consistency")
	if err != nil || index < 0 {
		t.Fatalf("dependency step index=%d err=%v", index, err)
	}
	const rootBeforeGo = "npm run npm:version\nnpm run source-hygiene\nnpm run command-contract:check\nnpm run command-family:check\nnpm run text-policy\nnpm run mermaid:check\nnpm run go:check\n"
	const goAfterDeps = "npm run go:test\nnpm run go:vet\nnpm run go:staticcheck\nnpm run go:actionlint\nnpm run go:vulncheck\n"
	const rootAfterGo = "npm run browser:check\nnpm run package:artifact\nnpm run self:receipt\nnpm run self:coverage\nnpm run release:closeout\n"
	for _, entry := range []struct {
		name, script, prefix, suffix string
		root, masked                 bool
	}{
		{"local composition", scripts["go:check"], "npm run go:fmt\n", goAfterDeps, false, false},
		{"CI source step", steps[index].Run, "", "", false, false},
		{"root composition", scripts["check"], rootBeforeGo + "npm run go:fmt\n", goAfterDeps + rootAfterGo, true, false},
		{"masked root control", scripts["check"] + " && true || true", rootBeforeGo + "npm run go:fmt\n", goAfterDeps + rootAfterGo, true, true},
	} {
		for _, failure := range []struct {
			name                              string
			tidyExit, verifyExit, goCheckExit int
		}{
			{"positive control", 0, 0, 0},
			{"tidy failure", 23, 0, 0},
			{"verify failure", 0, 29, 0},
			{"Go composition failure", 0, 0, 31},
		} {
			if failure.goCheckExit != 0 && !entry.root {
				continue
			}
			t.Run(entry.name+"/"+failure.name, func(t *testing.T) {
				dir := t.TempDir()
				trace := filepath.Join(dir, "trace")
				// Hook absence is proved by the separate map oracle, not emulated here.
				// Execute owner shell composition with controlled children, never real full gates.
				for name, body := range map[string]string{
					"npm": "#!/bin/sh\nprintf 'npm %s\\n' \"$*\" >> \"$TRACE\"\ncase \"$*\" in\n'run go:deps') exec /bin/sh -c \"$DEPS_SCRIPT\";;\n'run go:check') if [ \"$GO_CHECK_EXIT\" != 0 ]; then exit \"$GO_CHECK_EXIT\"; fi; exec /bin/sh -c \"$GO_CHECK_SCRIPT\";;\nesac\n",
					"go":  "#!/bin/sh\nprintf 'go %s\\n' \"$*\" >> \"$TRACE\"\ncase \"$*\" in\n'mod tidy -diff') exit \"$TIDY_EXIT\";;\n'mod verify') exit \"$VERIFY_EXIT\";;\n*) exit 91;;\nesac\n",
				} {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, "/bin/sh", "-c", entry.script)
				command.Dir = dir
				command.Env = []string{
					"PATH=" + dir + ":/usr/bin:/bin", "TRACE=" + trace,
					"DEPS_SCRIPT=" + scripts["go:deps"],
					"GO_CHECK_SCRIPT=" + scripts["go:check"],
					"TIDY_EXIT=" + strconv.Itoa(failure.tidyExit),
					"VERIFY_EXIT=" + strconv.Itoa(failure.verifyExit),
					"GO_CHECK_EXIT=" + strconv.Itoa(failure.goCheckExit),
				}
				output, runErr := command.CombinedOutput()
				wantExit := failure.tidyExit
				wantTrace := entry.prefix + "npm run go:deps\ngo mod tidy -diff\n"
				if wantExit == 0 {
					wantExit = failure.verifyExit
					wantTrace += "go mod verify\n"
				}
				if wantExit == 0 {
					wantTrace += entry.suffix
				}
				if failure.goCheckExit != 0 {
					wantExit = failure.goCheckExit
					wantTrace = rootBeforeGo
				}
				if entry.masked {
					wantExit = 0
				}
				if command.ProcessState == nil || command.ProcessState.ExitCode() != wantExit {
					t.Fatalf("exit state=%v, want %d: %v\n%s", command.ProcessState, wantExit, runErr, output)
				}
				actual, err := os.ReadFile(trace)
				if err != nil {
					t.Fatal(err)
				}
				if string(actual) != wantTrace {
					t.Fatalf("trace=%q, want %q", actual, wantTrace)
				}
				if entry.masked {
					changed := maps.Clone(scripts)
					changed["check"] = entry.script
					if err := validateGoDependencyGate(changed, workflow); err == nil {
						t.Fatal("oracle admitted the root control that masks nonzero child exits")
					}
				}
			})
		}
	}
}

func TestExistingReleasePathIsReadOnlyAndFailsOnDrift(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "release.yml"))
	job := workflow.Jobs["release-assets"]
	index, err := uniqueStepIndex(job.Steps, "Create GitHub Release")
	if err != nil || index < 0 {
		t.Fatalf("locate release step: index=%d err=%v", index, err)
	}
	run := job.Steps[index].Run
	if err := validateExistingReleasePath(run); err != nil {
		t.Fatalf("owner existing-release path: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(string) string
	}{
		{name: "upload", mutate: func(value string) string {
			return strings.Replace(value, "gh release download", "gh release upload", 1)
		}},
		{name: "edit", mutate: func(value string) string { return strings.Replace(value, "gh release view", "gh release edit", 1) }},
		{name: "delete", mutate: func(value string) string { return strings.Replace(value, "gh release view", "gh release delete", 1) }},
		{name: "api", mutate: func(value string) string { return strings.Replace(value, "gh release view", "gh api", 1) }},
		{name: "curl", mutate: func(value string) string {
			return strings.Replace(value, "gh release view", "curl https://example.invalid", 1)
		}},
		{name: "indirection", mutate: func(value string) string {
			return strings.Replace(value, "gh release view", `release_client=\"gh release view\"; $release_client`, 1)
		}},
		{name: "extra command", mutate: func(value string) string {
			return strings.Replace(value, "existing_dir=", "echo mutate\nexisting_dir=", 1)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := validateExistingReleasePath(test.mutate(run)); err == nil {
				t.Fatal("mutated existing-release path was admitted")
			}
		})
	}
}

func runnerLabels(raw any) []string {
	switch value := raw.(type) {
	case nil:
		return nil
	case string:
		return []string{value}
	case []any:
		result := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		sort.Strings(result)
		return result
	default:
		return nil
	}
}

var externalActionReference = regexp.MustCompile(`^[^/@[:space:]]+/[^@[:space:]]+@[0-9a-f]{40}$`)

var admittedWorkflowPaths = []string{
	".github/workflows/ci.yml",
	".github/workflows/codeql.yml",
	".github/workflows/osv-scanner.yml",
	".github/workflows/release.yml",
	".github/workflows/scorecard-publish.yml",
	".github/workflows/scorecard.yml",
	".github/workflows/semantic-diff.yml",
}

func validateWorkflowActionPins(root string) error {
	directory := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			return fmt.Errorf("unadmitted workflow entry %s", entry.Name())
		}
		actual = append(actual, filepath.ToSlash(filepath.Join(".github", "workflows", entry.Name())))
	}
	sort.Strings(actual)
	if !reflect.DeepEqual(actual, admittedWorkflowPaths) {
		return fmt.Errorf("workflow inventory=%v, want exact %v", actual, admittedWorkflowPaths)
	}
	for _, relative := range actual {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			return err
		}
		var workflow githubWorkflow
		if err := yaml.Unmarshal(content, &workflow); err != nil {
			return fmt.Errorf("parse %s: %w", relative, err)
		}
		if err := validateWorkflowActionReferences(workflow); err != nil {
			return fmt.Errorf("%s: %w", relative, err)
		}
	}
	return nil
}

func validateWorkflowActionReferences(workflow githubWorkflow) error {
	for jobID, job := range workflow.Jobs {
		if job.Uses != "" {
			if err := validateActionReference(job.Uses); err != nil {
				return fmt.Errorf("job %s: %w", jobID, err)
			}
		}
		for index, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			if err := validateActionReference(step.Uses); err != nil {
				return fmt.Errorf("job %s step %d: %w", jobID, index, err)
			}
		}
	}
	return nil
}

func validateActionReference(reference string) error {
	if strings.HasPrefix(reference, "./") {
		relative := strings.TrimPrefix(reference, "./")
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative)))
		if clean != relative || !strings.HasPrefix(relative, ".github/actions/") || strings.Contains(reference, `\`) {
			return fmt.Errorf("local action reference %q is not repository-confined", reference)
		}
		return nil
	}
	if !externalActionReference.MatchString(reference) {
		return fmt.Errorf("external action reference %q must use a full lowercase 40-hex commit", reference)
	}
	return nil
}

const existingReleaseReadOnlyBlockSHA256 = "b80fff2c67ae5b02d78f39e3551b18dc75b94800ebf0812063e07952342f5af5"

func validateExistingReleasePath(run string) error {
	startMarker := `if gh release view "$GITHUB_REF_NAME" >/dev/null 2>&1; then`
	endMarker := "\nfi\ngh release create"
	start := strings.Index(run, startMarker)
	if start < 0 {
		return errors.New("existing-release branch is missing")
	}
	endRelative := strings.Index(run[start:], endMarker)
	if endRelative < 0 {
		return errors.New("existing-release branch terminator is missing")
	}
	block := strings.TrimSpace(run[start : start+endRelative+len("\nfi")])
	for _, forbidden := range []string{
		"gh release upload",
		"gh release edit",
		"gh release delete",
		"gh api",
		"curl ",
	} {
		if strings.Contains(block, forbidden) {
			return fmt.Errorf("existing-release branch contains mutating or alternate provider command %q", forbidden)
		}
	}
	sum := sha256.Sum256([]byte(block))
	actual := fmt.Sprintf("%x", sum[:])
	if actual != existingReleaseReadOnlyBlockSHA256 {
		return fmt.Errorf("existing-release branch digest=%s, want exact owner digest %s", actual, existingReleaseReadOnlyBlockSHA256)
	}
	return nil
}
