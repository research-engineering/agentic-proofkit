package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

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
	for _, reference := range []string{"actions/checkout@v7", "actions/checkout@9c091bb"} {
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
	steps := strings.Split(script, " && ")
	indexes := map[string]int{}
	for index, step := range steps {
		if _, duplicate := indexes[step]; duplicate {
			return fmt.Errorf("root check contains duplicate step %q", step)
		}
		indexes[step] = index
	}
	for _, required := range []string{
		"npm run go:check",
		"npm run browser:check",
		"npm run package:artifact",
		"npm run self:receipt",
		"npm run self:coverage",
		"npm run release:closeout",
	} {
		if _, ok := indexes[required]; !ok {
			return fmt.Errorf("root check omits required proof gate %q", required)
		}
	}
	if indexes["npm run go:check"] > indexes["npm run browser:check"] {
		return errors.New("root check must run deterministic Go gates before browser gates")
	}
	return nil
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
