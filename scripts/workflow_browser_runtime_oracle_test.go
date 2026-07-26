package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
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
}
