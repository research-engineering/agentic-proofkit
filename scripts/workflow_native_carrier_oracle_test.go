package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
)

const nativeIntelArchitectureRun = `set -euo pipefail
test "$(uname -s)" = Darwin
test "$(uname -m)" = x86_64
test "$RUNNER_ARCH" = X64
translated="$(/usr/sbin/sysctl -in sysctl.proc_translated)"
case "$translated" in
  ""|0) ;;
  *) printf 'Native Intel execution is required.\n' >&2; exit 1 ;;
esac
`

const nativeIntelToolchainRun = `set -euo pipefail
test "$(node -p process.platform)" = darwin
test "$(node -p process.arch)" = x64
test "$(go env GOHOSTOS)" = darwin
test "$(go env GOHOSTARCH)" = amd64
`

func expectedNativeIntelCandidateJob() githubJob {
	run := func(name, command string) githubStep {
		return githubStep{Name: name, Run: command, runPresent: true}
	}
	action := func(name, use string, with map[string]any) githubStep {
		return githubStep{Name: name, Uses: use, With: with, usesPresent: true, withPresent: with != nil}
	}
	return githubJob{
		Name: "release candidate / native Intel macOS", Needs: "candidate", RunsOn: "macos-15-intel",
		TimeoutMinutes: 30, timeoutMinutesPresent: true, Permissions: map[string]any{"contents": "read"},
		Steps: []githubStep{
			run("Verify native Intel architecture", nativeIntelArchitectureRun),
			action("Checkout", "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", map[string]any{"persist-credentials": false}),
			action("Setup Node", "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1", map[string]any{"node-version": "26.11.1", "package-manager-cache": false}),
			action("Setup Go", "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", map[string]any{"go-version-file": "go.mod", "cache": false}),
			action("Setup Python", "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0", map[string]any{"python-version": "3.15.0"}),
			action("Install verified npm", "./.github/actions/setup-verified-npm", nil),
			run("Verify native Intel toolchain", nativeIntelToolchainRun),
			action("Download original candidate evidence", "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333", map[string]any{
				"name": "release-candidate-evidence-${{ github.sha }}", "path": "artifacts",
			}),
			run("Build source reference binaries", "go run ./internal/tools/packagebuild"),
			run("Verify installed npm candidate", "go run ./internal/tools/packageverify"),
			run("Verify installed Python candidate", "npm run python:verify"),
		},
	}
}

func validateNativeIntelCandidateWorkflow(workflow githubWorkflow, manifestBytes []byte) error {
	job, ok := workflow.Jobs["candidate-intel"]
	if !ok || !reflect.DeepEqual(job, expectedNativeIntelCandidateJob()) {
		return fmt.Errorf("native Intel candidate must retain its exact read-only architecture, artifact and installed-consumer steps")
	}
	if !reflect.DeepEqual(needsList(workflow.Jobs["publish-readiness"].Needs), []string{"candidate", "candidate-intel"}) {
		return fmt.Errorf("publish readiness must require both candidate and native Intel qualification")
	}
	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("parse native consumer package manifest: %w", err)
	}
	var scripts map[string]string
	if err := json.Unmarshal(manifest["scripts"], &scripts); err != nil {
		return fmt.Errorf("parse exact native consumer scripts: %w", err)
	}
	if scripts["python:verify"] != "go run ./internal/tools/pythonpackage verify" {
		return fmt.Errorf("native Python consumer must execute the exact wheel verifier")
	}
	for _, key := range []string{"prepython:verify", "postpython:verify"} {
		if _, present := scripts[key]; present {
			return fmt.Errorf("native Python consumer must omit lifecycle hooks")
		}
	}
	return nil
}

func TestReleaseNativeIntelCandidateAndBarrier(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "release.yml"))
	manifestBytes := readPackageManifestForTest(t)
	if err := validateNativeIntelCandidateWorkflow(workflow, manifestBytes); err != nil {
		t.Fatal(err)
	}
	mutants := []struct {
		name   string
		mutate func(*githubWorkflow)
	}{
		{"missing job", func(w *githubWorkflow) { delete(w.Jobs, "candidate-intel") }},
		{"publication bypass", func(w *githubWorkflow) {
			job := w.Jobs["publish-readiness"]
			job.Needs = "candidate"
			w.Jobs["publish-readiness"] = job
		}},
		{"ARM runner", func(w *githubWorkflow) {
			job := w.Jobs["candidate-intel"]
			job.RunsOn = "macos-15"
			w.Jobs["candidate-intel"] = job
		}},
		{"neutralized architecture", func(w *githubWorkflow) {
			job := w.Jobs["candidate-intel"]
			job.Steps[0].Run = "true"
			w.Jobs["candidate-intel"] = job
		}},
		{"publisher permission", func(w *githubWorkflow) {
			job := w.Jobs["candidate-intel"]
			job.Permissions = map[string]any{"contents": "read", "id-token": "write"}
			w.Jobs["candidate-intel"] = job
		}},
		{"repacked replacement", func(w *githubWorkflow) {
			job := w.Jobs["candidate-intel"]
			job.Steps[8].Run = "go run ./internal/tools/packagepack"
			w.Jobs["candidate-intel"] = job
		}},
		{"missing npm consumer", func(w *githubWorkflow) {
			job := w.Jobs["candidate-intel"]
			job.Steps = append(job.Steps[:9], job.Steps[10:]...)
			w.Jobs["candidate-intel"] = job
		}},
		{"missing Python consumer", func(w *githubWorkflow) {
			job := w.Jobs["candidate-intel"]
			job.Steps = job.Steps[:10]
			w.Jobs["candidate-intel"] = job
		}},
		{"ignored failure", func(w *githubWorkflow) {
			job := w.Jobs["candidate-intel"]
			job.continueOnErrorPresent = true
			job.ContinueOnError = false
			w.Jobs["candidate-intel"] = job
		}},
	}
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			candidate := cloneWorkflow(t, workflow)
			mutant.mutate(&candidate)
			if err := validateNativeIntelCandidateWorkflow(candidate, manifestBytes); err == nil {
				t.Fatal("mutated native qualification was admitted")
			}
		})
	}
	for _, change := range []struct{ key, value string }{
		{"python:verify", "true"},
		{"prepython:verify", "npm run python:package"},
		{"postpython:verify", ""},
	} {
		t.Run("manifest "+change.key, func(t *testing.T) {
			var manifest map[string]any
			if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
				t.Fatal(err)
			}
			manifest["scripts"].(map[string]any)[change.key] = change.value
			mutant, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateNativeIntelCandidateWorkflow(workflow, mutant); err == nil {
				t.Fatal("neutralized Python consumer was admitted")
			}
		})
	}
	for name, raw := range map[string]string{
		"case-shadowed scripts": `{"scripts":{"python:verify":"true"},"Scripts":{"python:verify":"go run ./internal/tools/pythonpackage verify"}}`,
		"missing exact scripts": `{"Scripts":{"python:verify":"go run ./internal/tools/pythonpackage verify"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateNativeIntelCandidateWorkflow(workflow, []byte(raw)); err == nil {
				t.Fatal("case-distinct manifest field replaced the exact npm scripts owner")
			}
		})
	}
}
