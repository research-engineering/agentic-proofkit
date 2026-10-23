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

const browserVisualJob = "browser-visual"

// readVisualReferenceImageForTest projects name:tag@index digest from the
// recorded visual reference environment.
func readVisualReferenceImageForTest(t *testing.T) (string, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "tests", "visual", "environment.json"))
	if err != nil {
		t.Fatal(err)
	}
	var environment struct {
		Image struct {
			Name            string            `json:"name"`
			Tag             string            `json:"tag"`
			IndexDigest     string            `json:"indexDigest"`
			Platform        string            `json:"platform"`
			PlatformDigests map[string]string `json:"platformDigests"`
		} `json:"image"`
	}
	if err := json.Unmarshal(raw, &environment); err != nil {
		t.Fatal(err)
	}
	image := environment.Image
	if image.Platform != "linux/arm64" || image.PlatformDigests[image.Platform] == "" {
		t.Fatalf("visual reference environment must record its linux/arm64 platform digest: %+v", image)
	}
	return image.Name + ":" + image.Tag + "@" + image.IndexDigest, image.Platform
}

// validateCIBrowserVisualJob checks the visual reference job against the
// recorded environment: the exact digest-pinned container on the native ARM
// runner, the exact ordered setup and gate steps, the capture gallery upload
// after every outcome with 30-day retention, and the record upload only after
// success.
func validateCIBrowserVisualJob(workflow githubWorkflow, referenceImage string) error {
	job, ok := workflow.Jobs[browserVisualJob]
	if !ok {
		return errors.New("ci workflow missing browser-visual job")
	}
	if runner, ok := job.RunsOn.(string); !ok || runner != "ubuntu-24.04-arm" {
		return fmt.Errorf("browser-visual runs-on=%v, want the native ARM runner ubuntu-24.04-arm", job.RunsOn)
	}
	container, ok := job.Container.(map[string]any)
	if !ok || container["image"] != referenceImage || container["options"] != ownedVisualContainerOptions || len(container) != 2 {
		return fmt.Errorf("browser-visual container=%v, want the recorded reference image %s", job.Container, referenceImage)
	}
	if ownedVisualContainerImage != referenceImage {
		return errors.New("owner container image differs from the recorded reference environment")
	}
	expected := []githubStep{
		{Name: "Checkout", Uses: "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", With: map[string]any{"persist-credentials": false}},
		{Name: "Setup Node", Uses: "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1", With: map[string]any{"node-version": "26.11.1", "package-manager-cache": false}},
		{Name: "Install verified npm", Uses: "./.github/actions/setup-verified-npm"},
		{Name: "Setup Go", Uses: "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", With: map[string]any{"go-version-file": "go.mod", "cache": true}},
		{Name: "Install locked browser tooling", Run: "npm ci --ignore-scripts"},
		{Name: "Run visual reference proof", Run: "npm run browser:visual -- --require-reference-environment"},
		{Name: "Upload visual reference captures", If: "${{ always() }}", Uses: "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9", With: map[string]any{
			"name":              "browser-visual-captures-${{ github.sha }}-${{ github.run_attempt }}",
			"path":              "artifacts/browser-run-*/captures\nartifacts/browser-run-*/candidate-references.json\nartifacts/browser-run-*/observed-environment.json\n",
			"if-no-files-found": "error",
			"retention-days":    30,
		}},
		{Name: "Upload visual reference proof", Uses: "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9", With: map[string]any{
			"name":              "browser-visual-proof-${{ github.sha }}",
			"path":              "artifacts/proofkit/browser-visual-proof.json",
			"if-no-files-found": "error",
			"retention-days":    14,
		}},
	}
	if len(job.Steps) != len(expected) {
		return fmt.Errorf("browser-visual step count=%d, want exact %d", len(job.Steps), len(expected))
	}
	for index, want := range expected {
		actual := job.Steps[index]
		if actual.Name != want.Name || actual.Uses != want.Uses || actual.Run != want.Run || actual.If != want.If ||
			!reflect.DeepEqual(actual.With, want.With) || actual.runPresent != (want.Run != "") ||
			actual.usesPresent != (want.Uses != "") || actual.withPresent != (want.With != nil) || actual.ifPresent != (want.If != "") {
			return fmt.Errorf("browser-visual step %d differs from exact owner step %q", index, want.Name)
		}
	}
	return nil
}

func TestCIBrowserVisualRunsTheRecordedReferenceEnvironment(t *testing.T) {
	workflow := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	referenceImage, _ := readVisualReferenceImageForTest(t)
	if err := validateCIRequiredAggregate(workflow); err != nil {
		t.Fatal(err)
	}
	if err := validateCIBrowserVisualJob(workflow, referenceImage); err != nil {
		t.Fatal(err)
	}
	// The contributor instructions run the same digest-pinned image.
	contributing, err := os.ReadFile(filepath.Join("..", "CONTRIBUTING.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contributing), "--platform linux/arm64 --user 1001 --ipc=host --init") || !strings.Contains(string(contributing), referenceImage) {
		t.Fatalf("CONTRIBUTING.md must run the recorded reference image %s", referenceImage)
	}
}

func TestCIBrowserVisualRejectsWeakenedReferenceGate(t *testing.T) {
	base := readWorkflowForTest(t, filepath.Join("..", ".github", "workflows", "ci.yml"))
	referenceImage, _ := readVisualReferenceImageForTest(t)
	validate := func(workflow githubWorkflow) error {
		return errors.Join(validateCIRequiredAggregate(workflow), validateCIBrowserVisualJob(workflow, referenceImage))
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
	withContainer := func(mutate func(map[string]any)) func(*githubWorkflow) {
		return func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			container := map[string]any{}
			for key, value := range job.Container.(map[string]any) {
				container[key] = value
			}
			mutate(container)
			job.Container = container
			workflow.Jobs[browserVisualJob] = job
		}
	}
	visualAggregateLine := "test \"${{ needs.browser-visual.result }}\" = \"success\"\n"
	cases := []struct {
		name   string
		mutate func(*githubWorkflow)
	}{
		{"unpinned image tag", withContainer(func(container map[string]any) {
			container["image"] = "mcr.microsoft.com/playwright:v1.63.0-noble"
		})},
		{"other image digest", withContainer(func(container map[string]any) {
			container["image"] = "mcr.microsoft.com/playwright:v1.63.0-noble@sha256:" + strings.Repeat("0", 64)
		})},
		{"platform manifest digest instead of the index", withContainer(func(container map[string]any) {
			container["image"] = "mcr.microsoft.com/playwright:v1.63.0-noble@sha256:a0f4498920a5dbac63196d9140ed738ef00470f27e2e74029abd8850b7bd5717"
		})},
		{"other image tag", withContainer(func(container map[string]any) {
			container["image"] = strings.Replace(container["image"].(string), "v1.63.0-noble", "v1.64.0-noble", 1)
		})},
		{"root container user", withContainer(func(container map[string]any) {
			container["options"] = "--ipc=host --init"
		})},
		{"container credentials", withContainer(func(container map[string]any) {
			container["credentials"] = map[string]any{"username": "shadow"}
		})},
		{"container removed", func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			job.Container, job.containerPresent = nil, false
			workflow.Jobs[browserVisualJob] = job
		}},
		{"container on another job", func(workflow *githubWorkflow) {
			job := workflow.Jobs["browser-runtime"]
			job.Container, job.containerPresent = workflow.Jobs[browserVisualJob].Container, true
			workflow.Jobs["browser-runtime"] = job
		}},
		{"x64 runner", func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			job.RunsOn = "ubuntu-24.04"
			workflow.Jobs[browserVisualJob] = job
		}},
		{"timeout lowered", func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			job.TimeoutMinutes = 1
			workflow.Jobs[browserVisualJob] = job
		}},
		{"reference environment no longer required", func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			job.Steps[stepIndex(job, "Run visual reference proof")].Run = "npm run browser:visual"
			workflow.Jobs[browserVisualJob] = job
		}},
		{"gate step neutralized", func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			job.Steps[stepIndex(job, "Run visual reference proof")].Run = "npm run browser:visual -- --require-reference-environment || true"
			workflow.Jobs[browserVisualJob] = job
		}},
		{"captures uploaded only on failure", func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			job.Steps[stepIndex(job, "Upload visual reference captures")].If = "${{ failure() }}"
			workflow.Jobs[browserVisualJob] = job
		}},
		{"captures uploaded only on success", func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			index := stepIndex(job, "Upload visual reference captures")
			job.Steps[index].If, job.Steps[index].ifPresent = "", false
			workflow.Jobs[browserVisualJob] = job
		}},
		{"record uploaded after a failure", func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			index := stepIndex(job, "Upload visual reference proof")
			job.Steps[index].If, job.Steps[index].ifPresent = "${{ always() }}", true
			workflow.Jobs[browserVisualJob] = job
		}},
		{"observed environment left out of the gallery", func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			index := stepIndex(job, "Upload visual reference captures")
			with := map[string]any{}
			for key, value := range job.Steps[index].With {
				with[key] = value
			}
			with["path"] = "artifacts/browser-run-*/captures\nartifacts/browser-run-*/candidate-references.json\n"
			job.Steps[index].With = with
			workflow.Jobs[browserVisualJob] = job
		}},
		{"unbounded gallery retention", func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			index := stepIndex(job, "Upload visual reference captures")
			with := map[string]any{}
			for key, value := range job.Steps[index].With {
				with[key] = value
			}
			delete(with, "retention-days")
			job.Steps[index].With = with
			workflow.Jobs[browserVisualJob] = job
		}},
		{"record uploaded before the gate", func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			gate, upload := stepIndex(job, "Run visual reference proof"), stepIndex(job, "Upload visual reference proof")
			job.Steps[gate], job.Steps[upload] = job.Steps[upload], job.Steps[gate]
			workflow.Jobs[browserVisualJob] = job
		}},
		{"dropped from aggregate needs", func(workflow *githubWorkflow) {
			gate := workflow.Jobs["ci-required-gate"]
			needs := []any{}
			for _, need := range gate.Needs.([]any) {
				if need != browserVisualJob {
					needs = append(needs, need)
				}
			}
			gate.Needs = needs
			workflow.Jobs["ci-required-gate"] = gate
		}},
		{"result unchecked by aggregate", func(workflow *githubWorkflow) {
			gate := workflow.Jobs["ci-required-gate"]
			gate.Steps[0].Run = strings.Replace(gate.Steps[0].Run, visualAggregateLine, "", 1)
			workflow.Jobs["ci-required-gate"] = gate
		}},
		{"job continue on error", func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			job.ContinueOnError = true
			workflow.Jobs[browserVisualJob] = job
		}},
		{"job environment", func(workflow *githubWorkflow) {
			job := workflow.Jobs[browserVisualJob]
			job.Env = map[string]any{"PLAYWRIGHT_BROWSERS_PATH": "/shadow"}
			workflow.Jobs[browserVisualJob] = job
		}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			workflow := cloneWorkflow(t, base)
			if !strings.Contains(workflow.Jobs["ci-required-gate"].Steps[0].Run, visualAggregateLine) {
				t.Fatal("owner aggregate lacks the browser-visual result line")
			}
			item.mutate(&workflow)
			if err := validate(workflow); err == nil {
				t.Fatal("weakened visual reference gate was admitted")
			}
		})
	}
}

func TestWorkflowContainerImagesArePinnedByDigest(t *testing.T) {
	for _, reference := range []string{
		ownedVisualContainerImage,
		"python:3.11.0-slim@sha256:" + strings.Repeat("a", 64),
		"registry.example:5000/team/image:1.0@sha256:" + strings.Repeat("b", 64),
	} {
		if err := validateContainerImageReference(reference); err != nil {
			t.Fatalf("digest-pinned reference %q was refused: %v", reference, err)
		}
	}
	for _, reference := range []string{
		"mcr.microsoft.com/playwright:v1.63.0-noble",
		"mcr.microsoft.com/playwright@sha256:" + strings.Repeat("a", 64),
		"mcr.microsoft.com/playwright:v1.63.0-noble@sha256:" + strings.Repeat("A", 64),
		"mcr.microsoft.com/playwright:v1.63.0-noble@sha256:" + strings.Repeat("a", 63),
		"mcr.microsoft.com/playwright:latest@sha512:" + strings.Repeat("a", 64),
		"",
	} {
		if err := validateContainerImageReference(reference); err == nil {
			t.Fatalf("unpinned or malformed container image reference %q was admitted", reference)
		}
	}
	ciPath := filepath.Join("..", ".github", "workflows", "ci.yml")
	ciRaw := readWorkflowBytesForTest(t, ciPath)
	ownerImageLine := "      image: " + ownedVisualContainerImage + "\n"
	ownerOptionsLine := "      options: " + ownedVisualContainerOptions + "\n"
	if !strings.Contains(string(ciRaw), "    container:\n"+ownerImageLine+ownerOptionsLine) {
		t.Fatal("owner ci workflow lacks the exact visual reference container")
	}
	for _, mutant := range []struct {
		name, anchor, replacement string
	}{
		{"unpinned image", ownerImageLine, "      image: mcr.microsoft.com/playwright:v1.63.0-noble\n"},
		{"floating image tag", ownerImageLine, "      image: mcr.microsoft.com/playwright:latest\n"},
		{"scalar container", "    container:\n" + ownerImageLine + ownerOptionsLine, "    container: " + ownedVisualContainerImage + "\n"},
		{"changed options", ownerOptionsLine, "      options: --ipc=host --init\n"},
		{"container credentials", ownerOptionsLine, ownerOptionsLine + "      credentials:\n        username: shadow\n"},
		{"container on the source job", "  source-quality:\n", "  source-quality:\n    container:\n" + ownerImageLine + ownerOptionsLine},
		{"unpinned container on the aggregate", "  ci-required-gate:\n", "  ci-required-gate:\n    container: ubuntu:24.04\n"},
	} {
		t.Run(mutant.name, func(t *testing.T) {
			assertClosedWorkflowMutationRejected(t, ciPath, ciRaw, mutant.anchor, mutant.replacement)
		})
	}
}
