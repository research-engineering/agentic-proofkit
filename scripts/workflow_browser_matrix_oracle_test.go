package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const browserMatrixJob = "browser-matrix"

func TestBrowserStaticCollectorRetainsEveryOracleSuite(t *testing.T) {
	files := []string{
		"scripts/browser-evidence-models.test.mjs",
		"scripts/browser-proof-execution.test.mjs",
		"scripts/browser-proof-inputs.test.mjs",
		"scripts/browser-selection-authority.test.mjs",
		"scripts/browser-visual-references.test.mjs",
		"scripts/browser-workspace-requests.test.mjs",
		"scripts/diagnostic-entrypoints.test.mjs",
		"scripts/stable-json.test.mjs",
		"tests/matrix/harness/oracles.test.mjs",
	}
	want := "tsc -p tsconfig.browser.json && node --test " + strings.Join(files, " ")
	validate := func(script string) error {
		if script != want {
			return errors.New("browser:static-check must run type checking and every owned oracle suite without suppression")
		}
		return nil
	}
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
	if err := validate(manifest.Scripts["browser:static-check"]); err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			for _, replacement := range []string{"", "scripts/not-an-oracle.test.mjs"} {
				if err := validate(strings.Replace(want, file, replacement, 1)); err == nil {
					t.Fatal("collector admitted an omitted or replaced suite")
				}
			}
		})
	}
	for _, script := range []string{strings.TrimPrefix(want, "tsc -p tsconfig.browser.json && "), want + " || true"} {
		if err := validate(script); err == nil {
			t.Fatal("collector admitted omitted type checking or failure suppression")
		}
	}
}

// validateCIBrowserMatrixJob checks the accessibility matrix job: the same
// digest-pinned reference environment container as the visual job on the
// native ARM runner, the exact ordered setup steps, one step per matrix family
// requiring the reference environment, the diagnostics upload only after a
// failure and the two family records uploaded only after success.
func validateCIBrowserMatrixJob(workflow githubWorkflow, referenceImage string) error {
	job, ok := workflow.Jobs[browserMatrixJob]
	if !ok {
		return errors.New("ci workflow missing browser-matrix job")
	}
	if runner, ok := job.RunsOn.(string); !ok || runner != "ubuntu-24.04-arm" {
		return fmt.Errorf("browser-matrix runs-on=%v, want the native ARM runner ubuntu-24.04-arm", job.RunsOn)
	}
	if job.Name != "quality / browser design matrix" || job.TimeoutMinutes != 20 {
		return fmt.Errorf("browser-matrix name=%q timeout=%v, want the owner name and 20 minutes", job.Name, job.TimeoutMinutes)
	}
	container, ok := job.Container.(map[string]any)
	if !ok || container["image"] != referenceImage || container["options"] != ownedVisualContainerOptions || len(container) != 2 {
		return fmt.Errorf("browser-matrix container=%v, want the recorded reference image %s", job.Container, referenceImage)
	}
	expected := []githubStep{
		{Name: "Checkout", Uses: "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", With: map[string]any{"persist-credentials": false}},
		{Name: "Setup Node", Uses: "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1", With: map[string]any{"node-version": "26.11.1", "package-manager-cache": false}},
		{Name: "Install verified npm", Uses: "./.github/actions/setup-verified-npm"},
		{Name: "Setup Go", Uses: "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", With: map[string]any{"go-version-file": "go.mod", "cache": true}},
		{Name: "Install locked browser tooling", Run: "npm ci --ignore-scripts"},
		{Name: "Run static matrix proof", Run: "npm run browser:matrix:static -- --require-reference-environment"},
		{Name: "Run workspace matrix proof", Run: "npm run browser:matrix:workspace -- --require-reference-environment"},
		{Name: "Upload matrix failure diagnostics", If: "${{ failure() }}", Uses: "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9", With: map[string]any{
			"name":              "browser-matrix-diagnostics-${{ github.sha }}-${{ github.run_attempt }}",
			"path":              "artifacts/browser-run-*/playwright-report.json\nartifacts/browser-run-*/test-results\n",
			"if-no-files-found": "error",
			"retention-days":    14,
		}},
		{Name: "Upload matrix proof", Uses: "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9", With: map[string]any{
			"name":              "browser-matrix-proof-${{ github.sha }}",
			"path":              "artifacts/proofkit/browser-matrix-static-proof.json\nartifacts/proofkit/browser-matrix-workspace-proof.json\n",
			"if-no-files-found": "error",
			"retention-days":    14,
		}},
	}
	if len(job.Steps) != len(expected) {
		return fmt.Errorf("browser-matrix step count=%d, want exact %d", len(job.Steps), len(expected))
	}
	for index, want := range expected {
		actual := job.Steps[index]
		if actual.Name != want.Name || actual.Uses != want.Uses || actual.Run != want.Run || actual.If != want.If ||
			!reflect.DeepEqual(actual.With, want.With) || actual.runPresent != (want.Run != "") ||
			actual.usesPresent != (want.Uses != "") || actual.withPresent != (want.With != nil) || actual.ifPresent != (want.If != "") {
			return fmt.Errorf("browser-matrix step %d differs from exact owner step %q", index, want.Name)
		}
	}
	return nil
}

func TestCIBrowserMatrixRunsBothFamiliesInTheReferenceEnvironment(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	referenceImage, _ := readVisualReferenceImageForTest(t)
	if err := validateCIRequiredAggregate(workflow); err != nil {
		t.Fatal(err)
	}
	if err := validateCIBrowserMatrixJob(workflow, referenceImage); err != nil {
		t.Fatal(err)
	}
}

func TestCIBrowserMatrixRejectsWeakenedMatrixGate(t *testing.T) {
	base := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	referenceImage, _ := readVisualReferenceImageForTest(t)
	validate := func(workflow githubWorkflow) error {
		return errors.Join(validateCIRequiredAggregate(workflow), validateCIBrowserMatrixJob(workflow, referenceImage))
	}
	if err := validate(cloneWorkflow(t, base)); err != nil {
		t.Fatalf("owner workflow clone: %v", err)
	}
	stepIndex := func(job githubJob, name string) int {
		index, err := uniqueStepIndex(job.Steps, name)
		if err != nil || index < 0 {
			t.Fatalf("locate %q: index=%d err=%v", name, index, err)
		}
		return index
	}
	withJob := func(mutate func(*githubJob)) func(*githubWorkflow) {
		return func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserMatrixJob]
			mutate(&job)
			workflow.Jobs[browserMatrixJob] = job
		}
	}
	withContainer := func(mutate func(map[string]any)) func(*githubWorkflow) {
		return withJob(func(job *githubJob) {
			container := map[string]any{}
			for key, value := range job.Container.(map[string]any) {
				container[key] = value
			}
			mutate(container)
			job.Container = container
		})
	}
	matrixAggregateLine := "test \"${{ needs.browser-matrix.result }}\" = \"success\"\n"
	cases := []struct {
		name   string
		mutate func(*githubWorkflow)
	}{
		{"unpinned image tag", withContainer(func(container map[string]any) { container["image"] = "mcr.microsoft.com/playwright:v1.63.0-noble" })},
		{"platform manifest digest instead of the index", withContainer(func(container map[string]any) {
			container["image"] = "mcr.microsoft.com/playwright:v1.63.0-noble@sha256:a0f4498920a5dbac63196d9140ed738ef00470f27e2e74029abd8850b7bd5717"
		})},
		{"root container user", withContainer(func(container map[string]any) { container["options"] = "--ipc=host --init" })},
		{"container removed", withJob(func(job *githubJob) { job.Container, job.containerPresent = nil, false })},
		{"x64 runner", withJob(func(job *githubJob) { job.RunsOn = "ubuntu-24.04" })},
		{"timeout raised past the budget", withJob(func(job *githubJob) { job.TimeoutMinutes = 30 })},
		{"static family dropped", withJob(func(job *githubJob) {
			index := stepIndex(*job, "Run static matrix proof")
			job.Steps = append(job.Steps[:index:index], job.Steps[index+1:]...)
		})},
		{"workspace family without the reference environment", withJob(func(job *githubJob) {
			job.Steps[stepIndex(*job, "Run workspace matrix proof")].Run = "npm run browser:matrix:workspace"
		})},
		{"static family neutralized", withJob(func(job *githubJob) {
			job.Steps[stepIndex(*job, "Run static matrix proof")].Run = "npm run browser:matrix:static -- --require-reference-environment || true"
		})},
		{"families merged into the composite script", withJob(func(job *githubJob) {
			job.Steps[stepIndex(*job, "Run static matrix proof")].Run = "npm run browser:matrix -- --require-reference-environment"
		})},
		{"records uploaded after a failure", withJob(func(job *githubJob) {
			index := stepIndex(*job, "Upload matrix proof")
			job.Steps[index].If, job.Steps[index].ifPresent = "${{ always() }}", true
		})},
		{"workspace record left out", withJob(func(job *githubJob) {
			index := stepIndex(*job, "Upload matrix proof")
			with := map[string]any{}
			for key, value := range job.Steps[index].With {
				with[key] = value
			}
			with["path"] = "artifacts/proofkit/browser-matrix-static-proof.json\n"
			job.Steps[index].With = with
		})},
		{"diagnostics uploaded on success", withJob(func(job *githubJob) {
			index := stepIndex(*job, "Upload matrix failure diagnostics")
			job.Steps[index].If, job.Steps[index].ifPresent = "", false
		})},
		{"dropped from aggregate needs", func(workflow *githubWorkflow) {
			gate := workflow.Jobs["ci-required-gate"]
			needs := []any{}
			for _, need := range gate.Needs.([]any) {
				if need != browserMatrixJob {
					needs = append(needs, need)
				}
			}
			gate.Needs = needs
			workflow.Jobs["ci-required-gate"] = gate
		}},
		{"result unchecked by aggregate", func(workflow *githubWorkflow) {
			gate := workflow.Jobs["ci-required-gate"]
			gate.Steps[0].Run = strings.Replace(gate.Steps[0].Run, matrixAggregateLine, "", 1)
			workflow.Jobs["ci-required-gate"] = gate
		}},
		{"job continue on error", withJob(func(job *githubJob) { job.ContinueOnError = true })},
		{"job environment", withJob(func(job *githubJob) { job.Env = map[string]any{"PLAYWRIGHT_BROWSERS_PATH": "/shadow"} })},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			workflow := cloneWorkflow(t, base)
			if !strings.Contains(workflow.Jobs["ci-required-gate"].Steps[0].Run, matrixAggregateLine) {
				t.Fatal("owner aggregate lacks the browser-matrix result line")
			}
			item.mutate(&workflow)
			if err := validate(workflow); err == nil {
				t.Fatal("weakened accessibility matrix gate was admitted")
			}
		})
	}
}
