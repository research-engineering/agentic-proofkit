package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestCIBrowserRuntimeInstallsEnginesBeforeProofAndRetainsOnlySuccessfulEvidence(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	job, ok := workflow.Jobs["browser-runtime"]
	if !ok {
		t.Fatal("ci workflow missing browser-runtime job")
	}
	installIndex, err := uniqueStepIndex(job.Steps, "Install pinned browser engines")
	if err != nil {
		t.Fatal(err)
	}
	proofIndex, err := uniqueStepIndex(job.Steps, "Run browser proof")
	if err != nil {
		t.Fatal(err)
	}
	uploadIndex, err := uniqueStepIndex(job.Steps, "Upload browser proof")
	if err != nil {
		t.Fatal(err)
	}
	if !(installIndex < proofIndex && proofIndex < uploadIndex) {
		t.Fatalf("browser runtime order install=%d proof=%d upload=%d", installIndex, proofIndex, uploadIndex)
	}
	if job.Steps[installIndex].Run != "npx playwright install --with-deps chromium firefox webkit" || job.Steps[proofIndex].Run != "npm run browser:check" {
		t.Fatalf("browser runtime commands are not exact: install=%q proof=%q", job.Steps[installIndex].Run, job.Steps[proofIndex].Run)
	}
	assertUbuntuMirrorPreparationForTest(t, job.Steps, installIndex)
	upload := job.Steps[uploadIndex]
	if usesAlwaysStatusCheck(upload.If) || upload.With["if-no-files-found"] != "error" || upload.With["path"] != "artifacts/proofkit/browser-runtime-proof.json" {
		t.Fatalf("browser proof upload is not fail-closed success evidence: %#v", upload)
	}
}

func TestCIBrowserRuntimeRetainsFailureDiagnosticsWithoutPublishingProof(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	job, ok := workflow.Jobs["browser-runtime"]
	if !ok {
		t.Fatal("ci workflow missing browser-runtime job")
	}
	proofIndex, err := uniqueStepIndex(job.Steps, "Run browser proof")
	if err != nil {
		t.Fatal(err)
	}
	diagnosticsIndex, err := uniqueStepIndex(job.Steps, "Upload browser failure diagnostics")
	if err != nil {
		t.Fatal(err)
	}
	successIndex, err := uniqueStepIndex(job.Steps, "Upload browser proof")
	if err != nil {
		t.Fatal(err)
	}
	if !(proofIndex < diagnosticsIndex && diagnosticsIndex < successIndex) {
		t.Fatalf("browser runtime order proof=%d diagnostics=%d success=%d", proofIndex, diagnosticsIndex, successIndex)
	}
	diagnostics := job.Steps[diagnosticsIndex]
	success := job.Steps[successIndex]
	if normalizedExpression(diagnostics.If) != "failure()" {
		t.Fatalf("browser diagnostics condition=%q, want exact failure()", diagnostics.If)
	}
	if strings.TrimSpace(success.If) != "" {
		t.Fatalf("browser proof success upload has non-default condition %q", success.If)
	}
	if diagnostics.Uses == "" || diagnostics.Uses != success.Uses {
		t.Fatalf("browser diagnostics action=%q, want pinned proof upload action %q", diagnostics.Uses, success.Uses)
	}
	wantPath := "artifacts/browser-run-*/playwright-report.json\nartifacts/browser-run-*/test-results"
	if strings.TrimSpace(fmt.Sprint(diagnostics.With["path"])) != wantPath ||
		diagnostics.With["if-no-files-found"] != "error" ||
		fmt.Sprint(diagnostics.With["retention-days"]) != "14" ||
		diagnostics.With["name"] != "browser-runtime-diagnostics-${{ github.sha }}-${{ github.run_attempt }}" {
		t.Fatalf("browser failure diagnostics upload is not exact and bounded: %#v", diagnostics)
	}
}

func TestReleaseCandidateInstallsBrowserEnginesBeforePackageGate(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "release.yml"))
	job, ok := workflow.Jobs["candidate"]
	if !ok {
		t.Fatal("release workflow missing candidate job")
	}
	installIndex, err := uniqueStepIndex(job.Steps, "Install pinned browser engines")
	if err != nil {
		t.Fatal(err)
	}
	gateIndex, err := uniqueStepIndex(job.Steps, "Run package gate")
	if err != nil {
		t.Fatal(err)
	}
	if installIndex >= gateIndex || job.Steps[installIndex].Run != "npx playwright install --with-deps chromium firefox webkit" || job.Steps[gateIndex].Run != "npm run check" {
		t.Fatalf("release browser prerequisite is not fail-closed before package gate: install=%#v gate=%#v", job.Steps[installIndex], job.Steps[gateIndex])
	}
	assertUbuntuMirrorPreparationForTest(t, job.Steps, installIndex)
}

func assertUbuntuMirrorPreparationForTest(t *testing.T, steps []githubStep, installIndex int) {
	t.Helper()
	index, err := uniqueStepIndex(steps, "Select official Ubuntu package mirrors")
	if err != nil {
		t.Fatal(err)
	}
	step := steps[index]
	if index >= installIndex || step.Uses != "./.github/actions/setup-ubuntu-mirrors" ||
		step.Run != "" || step.ifPresent || step.continueOnErrorPresent || len(step.With) != 0 || len(step.Env) != 0 {
		t.Fatalf("Ubuntu mirror preparation is not an unconditional shared prerequisite: %#v", step)
	}
}

func TestUbuntuMirrorActionPreservesExactPriorityAndRejectsFailedPreparation(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", ".github", "actions", "setup-ubuntu-mirrors", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
		Runs        struct {
			Using string `yaml:"using"`
			Steps []struct {
				Name  string `yaml:"name"`
				Shell string `yaml:"shell"`
				Run   string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&action); err != nil {
		t.Fatal(err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("Ubuntu mirror action must contain exactly one YAML document: %v", err)
	}
	if action.Runs.Using != "composite" || len(action.Runs.Steps) != 1 || action.Runs.Steps[0].Shell != "bash" {
		t.Fatalf("Ubuntu mirror action has an unexpected execution surface: %#v", action)
	}
	const want = "https://archive.ubuntu.com/ubuntu/\tpriority:1\nhttps://security.ubuntu.com/ubuntu/\tpriority:2\nhttp://azure.archive.ubuntu.com/ubuntu/\tpriority:3\n"
	for _, control := range []struct {
		name, setup, want  string
		failed             bool
		mayCreateEmptyFile bool
	}{
		{name: "exact signed-repository mirror order", want: want},
		{name: "missing mirror list", setup: "test() { [[ \"$*\" != '-f /etc/apt/apt-mirrors.txt' ]]; }", failed: true},
		{name: "symlink mirror list", setup: "test() { [[ \"$*\" != '! -L /etc/apt/apt-mirrors.txt' ]]; }", failed: true},
		{name: "source interface absent", setup: "grep() { return 1; }", failed: true},
		{name: "writer failure", setup: "sudo() { return 7; }", failed: true},
		{name: "upstream pipe failure", setup: "printf() { return 7; }", failed: true, mayCreateEmptyFile: true},
	} {
		t.Run(control.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "mirrors.txt")
			// Replace privileged host effects, but execute the actual action shell.
			harness := `test() {
  case "$*" in
    '-f /etc/apt/apt-mirrors.txt'|'! -L /etc/apt/apt-mirrors.txt') return 0 ;;
    *) return 2 ;;
  esac
}
grep() {
  [[ "$*" == '-Fq mirror+file:/etc/apt/apt-mirrors.txt /etc/apt/sources.list.d/ubuntu.sources' ]]
}
sudo() {
  [[ "$*" == 'tee /etc/apt/apt-mirrors.txt' ]] || return 2
  command tee "$MIRROR_TEST_OUTPUT"
}
` + control.setup + "\n" + action.Runs.Steps[0].Run
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-c", harness)
			command.Env = append(os.Environ(), "MIRROR_TEST_OUTPUT="+output)
			log, err := command.CombinedOutput()
			if ctx.Err() != nil || (err != nil) != control.failed {
				t.Fatalf("action failure=%v timeout=%v, want failure=%v; output=%s", err, ctx.Err(), control.failed, log)
			}
			actual, readErr := os.ReadFile(output)
			if control.want == "" {
				if !control.mayCreateEmptyFile && !os.IsNotExist(readErr) {
					t.Fatalf("failed prerequisite reached the privileged writer: bytes=%q error=%v", actual, readErr)
				}
				if readErr != nil && !os.IsNotExist(readErr) {
					t.Fatal(readErr)
				}
				if len(actual) != 0 {
					t.Fatalf("failed preparation wrote mirror bytes: %q", actual)
				}
			} else if readErr != nil || string(actual) != control.want {
				t.Fatalf("mirrors=%q error=%v, want exact %q", actual, readErr, control.want)
			}
		})
	}
}
