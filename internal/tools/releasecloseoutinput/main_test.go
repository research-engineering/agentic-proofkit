package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/command/completioncriteria"
	"github.com/research-engineering/agentic-proofkit/internal/command/proofreceiptadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/specproofbundleadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/tools/commandoracle"
	"github.com/research-engineering/agentic-proofkit/internal/tools/packageartifactrecord"
	"github.com/research-engineering/agentic-proofkit/internal/tools/releasechange"
)

const (
	testNPMPackageName    = "@research-engineering/agentic-proofkit"
	testNPMTarballName    = "research-engineering-agentic-proofkit-1.2.3.tgz"
	testPythonPackageName = "agentic-proofkit"
	testPythonWheelName   = "agentic_proofkit-1.2.3-py3-none-any.whl"
)

var (
	completeFixtureBaseErr  error
	completeFixtureBaseOnce sync.Once
	completeFixtureBaseRoot string
)

func TestMain(m *testing.M) {
	commandOracleValidateCurrent = func(context.Context, string, commandoracle.Evidence) error { return nil }
	exitCode := m.Run()
	if completeFixtureBaseRoot != "" {
		_ = os.RemoveAll(completeFixtureBaseRoot)
	}
	os.Exit(exitCode)
}

func TestBuildInputProducesAdmittedSatisfiedCloseout(t *testing.T) {
	root := completeFixture(t)

	input, err := buildInput(root)
	if err != nil {
		t.Fatalf("buildInput() error = %v", err)
	}
	assertCloseoutOutcome(t, input, 0, "passed")
	assertCriterionStatus(t, input, "proofkit.release_closeout.package_artifacts", "satisfied")
	assertCriterionStatus(t, input, "proofkit.release_closeout.provider_publication_advisory", "advisory_skipped")
	assertCriterionInventory(t, input)
}

func TestCompleteFixtureCopiesAreIsolated(t *testing.T) {
	first := completeFixture(t)
	second := completeFixture(t)
	firstSource := filepath.Join(first, "source.txt")
	secondSource := filepath.Join(second, "source.txt")
	writeFile(t, firstSource, "mutated\n")
	content, err := os.ReadFile(secondSource)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "source-v1\n" {
		t.Fatalf("fixture copy mutation leaked across tests: %q", content)
	}
}

func TestBuildInputAdmitsGitHubActionsAdvisorySelfEvidence(t *testing.T) {
	root := completeFixture(t)
	writeGitHubActionsSelfEvidence(t, root)

	input, err := buildInput(root)
	if err != nil {
		t.Fatalf("buildInput() error = %v", err)
	}
	assertCriterionStatus(t, input, "proofkit.release_closeout.self_evidence", "satisfied")
	assertCloseoutOutcome(t, input, 0, "passed")
}

func TestCompleteFixtureSelfEvidenceComponentsMatch(t *testing.T) {
	root := completeFixture(t)
	cases := []struct {
		name  string
		match func(string, string) bool
		path  string
	}{
		{name: "proof receipts", match: proofReceiptSetMatches, path: "artifacts/proofkit/self-hosting-proof-receipts.json"},
		{name: "producer policy", match: receiptProducerPolicyMatches, path: "artifacts/proofkit/self-hosting-receipt-producer-admission.json"},
		{name: "spec proof bundle", match: specProofBundleMatches, path: "artifacts/proofkit/self-hosting-spec-proof-bundle.json"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if !item.match(root, item.path) {
				if item.path == "artifacts/proofkit/self-hosting-spec-proof-bundle.json" {
					raw := readJSONMap(t, filepath.Join(root, filepath.FromSlash(item.path)))
					report, exitCode, ownerErr := specproofbundleadmission.Build(raw)
					t.Logf("spec bundle owner exit=%d state=%s err=%v diagnostics=%#v", exitCode, report.State, ownerErr, report.Diagnostics)
				}
				t.Fatalf("%s must match its owner-admitted closeout contract", item.path)
			}
		})
	}
}

func TestCompleteFixtureSelfEvidenceSnapshotMatches(t *testing.T) {
	root := completeFixture(t)
	snapshot, err := readSelfEvidenceSnapshot(root)
	if err != nil {
		t.Fatalf("readSelfEvidenceSnapshot() error = %v", err)
	}
	checks := []struct {
		name string
		ok   bool
	}{
		{name: "coverage metrics", ok: coverageMetricsRecordMatches(snapshot.coverageMetrics.value, snapshot.cliContractCommands)},
		{name: "proof receipt report", ok: reportRecordMatches(snapshot.proofReceiptReport.value, "proofkit.proof-receipt-admission", "proofkit.self-hosting.proof-receipts", "passed", []string{"proofkit.proof-receipt-admission.boundary", "proofkit.proof-receipt-admission.receipts"})},
		{name: "proof receipts", ok: proofReceiptDocumentMatches(snapshot.proofReceipts)},
		{name: "producer report", ok: reportRecordMatches(snapshot.producerReport.value, "proofkit.receipt-producer-admission", "proofkit.receipt-producer-policy", "passed", []string{"proofkit.receipt-producer-admission.boundary", "proofkit.receipt-producer-admission.coverage", "proofkit.receipt-producer-admission.receipts"})},
		{name: "producer policy", ok: receiptProducerDocumentMatches(snapshot.producerPolicy)},
		{name: "bundle report", ok: reportRecordMatches(snapshot.specProofBundleReport.value, "proofkit.spec-proof-bundle-admission", "proofkit.self-hosting.spec-proof-bundle", "passed", []string{"proofkit.spec-proof-bundle-admission.accepted"})},
		{name: "bundle", ok: specProofBundleDocumentMatches(snapshot.specProofBundle)},
		{name: "cross-file identity", ok: snapshot.identityConsistent(snapshot.execution)},
	}
	for _, check := range checks {
		if !check.ok {
			t.Errorf("coherent snapshot rejected %s", check.name)
		}
	}
	if !snapshot.valid() {
		t.Fatal("coherent snapshot must be valid")
	}
}

func TestSelfEvidenceRejectsFieldsUnknownToCanonicalOwners(t *testing.T) {
	cases := []struct {
		match func(string, string) bool
		path  string
	}{
		{match: proofReceiptSetMatches, path: "artifacts/proofkit/self-hosting-proof-receipts.json"},
		{match: receiptProducerPolicyMatches, path: "artifacts/proofkit/self-hosting-receipt-producer-admission.json"},
		{match: specProofBundleMatches, path: "artifacts/proofkit/self-hosting-spec-proof-bundle.json"},
	}
	for _, item := range cases {
		t.Run(filepath.Base(item.path), func(t *testing.T) {
			root := completeFixture(t)
			path := filepath.Join(root, filepath.FromSlash(item.path))
			record := readJSONMap(t, path)
			record["unknownOwnerField"] = true
			writeJSON(t, path, record)
			if item.match(root, item.path) {
				t.Fatalf("%s accepted a field rejected by its canonical owner", item.path)
			}
		})
	}
}

func TestBuildInputRejectsMixedSelfEvidenceIdentity(t *testing.T) {
	root := completeFixture(t)
	writeMixedSelfEvidenceIdentity(t, root)

	input, err := buildInput(root)
	if err != nil {
		t.Fatalf("buildInput() error = %v", err)
	}
	assertCriterionStatus(t, input, "proofkit.release_closeout.self_evidence", "missing_evidence")
	assertCloseoutOutcome(t, input, 1, "failed")
}

func TestBuildInputFailsClosedForEachBlockingEvidenceClass(t *testing.T) {
	if !commandRouteMetricsProducerReachable(producerReachableCommandRouteMetricsFixture(), producerReachableCLIContractCommands()) {
		t.Fatal("release closeout rejected a coverage-metrics producer-reachable count relation")
	}
	cases := []struct {
		name        string
		criterionID string
		mutate      func(string)
	}{
		{
			name:        "missing package tarball",
			criterionID: "proofkit.release_closeout.package_artifacts",
			mutate: func(root string) {
				mustRemove(t, filepath.Join(root, "artifacts", "package", testNPMTarballName))
			},
		},
		{
			name:        "symlinked package tarball",
			criterionID: "proofkit.release_closeout.package_artifacts",
			mutate: func(root string) {
				tarballPath := filepath.Join(root, "artifacts", "package", testNPMTarballName)
				mustRemove(t, tarballPath)
				outsidePath := filepath.Join(t.TempDir(), "outside.tgz")
				writeFile(t, outsidePath, "package")
				if err := os.Symlink(outsidePath, tarballPath); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:        "symlinked package directory",
			criterionID: "proofkit.release_closeout.package_artifacts",
			mutate: func(root string) {
				replaceDirectoryWithSymlink(t, filepath.Join(root, "artifacts", "package"))
			},
		},
		{
			name:        "traversing package identity",
			criterionID: "proofkit.release_closeout.package_artifacts",
			mutate: func(root string) {
				manifest := readJSONMap(t, filepath.Join(root, "package.json"))
				manifest["name"] = "scope/../../../../../outside"
				writeJSON(t, filepath.Join(root, "package.json"), manifest)
			},
		},
		{
			name:        "stale npm pack metadata",
			criterionID: "proofkit.release_closeout.package_artifacts",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "package", "npm-pack.json"), []any{
					map[string]any{"name": testNPMPackageName, "version": "9.9.9", "filename": testNPMTarballName},
				})
			},
		},
		{
			name:        "stale npm pack shasum",
			criterionID: "proofkit.release_closeout.package_artifacts",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "package", "npm-pack.json"), []any{
					map[string]any{
						"filename":  testNPMTarballName,
						"integrity": testNPMIntegrity([]byte("package")),
						"name":      testNPMPackageName,
						"shasum":    strings.Repeat("0", 40),
						"version":   "1.2.3",
					},
				})
			},
		},
		{
			name:        "stale npm pack integrity",
			criterionID: "proofkit.release_closeout.package_artifacts",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "package", "npm-pack.json"), []any{
					map[string]any{
						"filename":  testNPMTarballName,
						"integrity": "sha512-" + strings.Repeat("A", 88),
						"name":      testNPMPackageName,
						"shasum":    testSHA1([]byte("package")),
						"version":   "1.2.3",
					},
				})
			},
		},
		{
			name:        "missing Python wheel",
			criterionID: "proofkit.release_closeout.python_wrappers",
			mutate: func(root string) {
				mustRemove(t, filepath.Join(root, "artifacts", "pypi", testPythonWheelName))
			},
		},
		{
			name:        "symlinked Python artifact directory",
			criterionID: "proofkit.release_closeout.python_wrappers",
			mutate: func(root string) {
				replaceDirectoryWithSymlink(t, filepath.Join(root, "artifacts", "pypi"))
			},
		},
		{
			name:        "stale Python package metadata",
			criterionID: "proofkit.release_closeout.python_wrappers",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "pypi", "python-packages.json"), map[string]any{
					"packageName":    testPythonPackageName,
					"packageVersion": "1.2.3",
					"packages": []any{
						map[string]any{"name": testPythonPackageName, "version": "9.9.9", "filename": testPythonWheelName},
					},
				})
			},
		},
		{
			name:        "stale Python wheel digest",
			criterionID: "proofkit.release_closeout.python_wrappers",
			mutate: func(root string) {
				path := filepath.Join(root, "artifacts", "pypi", "python-packages.json")
				record := readJSONMap(t, path)
				record["packages"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64)
				writeJSON(t, path, record)
			},
		},
		{
			name:        "stale Python binary digest",
			criterionID: "proofkit.release_closeout.python_wrappers",
			mutate: func(root string) {
				path := filepath.Join(root, "artifacts", "pypi", "python-packages.json")
				record := readJSONMap(t, path)
				record["packages"].([]any)[0].(map[string]any)["binarySha256"] = strings.Repeat("0", 64)
				writeJSON(t, path, record)
			},
		},
		{
			name:        "missing SBOM",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				mustRemove(t, filepath.Join(root, "artifacts", "release", "sbom.cdx.json"))
			},
		},
		{
			name:        "release notes without rollback instructions",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				writeFile(t, filepath.Join(root, "artifacts", "release", "release-notes.md"), "# notes\n\ninstall only\n")
			},
		},
		{
			name:        "release notes without package rollback target",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				writeFile(t, filepath.Join(root, "artifacts", "release", "release-notes.md"), "# notes\n\nrollback with npm install\n")
			},
		},
		{
			name:        "change record summary drift from release notes",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				path := filepath.Join(root, "release", "change-record.v2.json")
				record := readJSONMap(t, path)
				additions := record["additions"].([]any)
				additions[0].(map[string]any)["summary"] = "Changed without regenerating release notes."
				writeJSON(t, path, record)
			},
		},
		{
			name:        "change record version drift from package and release notes",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				path := filepath.Join(root, "release", "change-record.v2.json")
				record := readJSONMap(t, path)
				record["version"] = "1.2.4"
				writeJSON(t, path, record)
			},
		},
		{
			name:        "missing metadata checksums",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				mustRemove(t, filepath.Join(root, "artifacts", "release", "metadata-checksums.sha256"))
			},
		},
		{
			name:        "stale metadata checksums",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				writeFile(t, filepath.Join(root, "artifacts", "release", "metadata-checksums.sha256"), strings.Repeat("a", 64)+"  release-manifest.json\n")
			},
		},
		{
			name:        "missing retained evidence checksums",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "release", "github-release.json"), map[string]any{
					"tagName": "v1.2.3",
					"assets":  []any{},
				})
			},
		},
		{
			name:        "retained evidence manifest without targets",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				writeFile(t, filepath.Join(root, "artifacts", "retained-evidence-checksums.sha256"), strings.Repeat("a", 64)+"  release/github-release.json\n")
			},
		},
		{
			name:        "unbound retained attestation without manifest",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "attestations", "unbound.json"), map[string]any{"state": "unbound"})
			},
		},
		{
			name:        "empty retained attestation namespace",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				if err := os.MkdirAll(filepath.Join(root, "artifacts", "attestations"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:        "symlinked retained attestation namespace",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				target := t.TempDir()
				writeJSON(t, filepath.Join(target, "github-artifact-attestations.json"), map[string]any{"state": "redirected"})
				if err := os.Symlink(target, filepath.Join(root, "artifacts", "attestations")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:        "stale retained evidence checksums",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "release", "github-release.json"), map[string]any{
					"tagName": "v1.2.3",
					"assets":  []any{},
				})
				writeJSON(t, filepath.Join(root, "artifacts", "attestations", "github-artifact-attestations.json"), map[string]any{"state": "not_published"})
				writeFile(t, filepath.Join(root, "artifacts", "retained-evidence-checksums.sha256"), strings.Repeat("a", 64)+"  release/github-release.json\n")
			},
		},
		{
			name:        "planned PyPI without non-claim",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "release", "release-manifest.json"), releaseManifestFixture(false))
			},
		},
		{
			name:        "planned PyPI with unrelated non-claim",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				manifest := releaseManifestFixture(true)
				channels := manifest["channels"].([]any)
				channels[3].(map[string]any)["nonClaims"] = []any{"This does not claim vulnerability absence."}
				writeJSON(t, filepath.Join(root, "artifacts", "release", "release-manifest.json"), manifest)
			},
		},
		{
			name:        "planned PyPI with inverted non-claim",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				manifest := releaseManifestFixture(true)
				channels := manifest["channels"].([]any)
				channels[3].(map[string]any)["nonClaims"] = []any{"PyPI is a dependency authority for this version without PyPI package evidence."}
				writeJSON(t, filepath.Join(root, "artifacts", "release", "release-manifest.json"), manifest)
			},
		},
		{
			name:        "candidate PyPI registry authority",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "release", "release-manifest.json"), releaseManifestFixtureWithPyPI("candidate", true))
			},
		},
		{
			name:        "workflow publication without trusted publisher identity",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "release", "release-manifest.json"), releaseManifestFixtureWithNpmPublication("published_by_workflow", nil))
			},
		},
		{
			name:        "mixed publication without trusted publisher identity",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "release", "release-manifest.json"), releaseManifestFixtureWithNpmPublication("mixed", nil))
			},
		},
		{
			name:        "candidate channel with trusted publisher identity",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				manifest := releaseManifestFixture(true)
				channels := manifest["channels"].([]any)
				channels[0].(map[string]any)["trustedPublisher"] = trustedPublisherFixture("npm-production", "publish")
				writeJSON(t, filepath.Join(root, "artifacts", "release", "release-manifest.json"), manifest)
			},
		},
		{
			name:        "candidate npm registry channel without non-claim",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				manifest := releaseManifestFixture(true)
				channels := manifest["channels"].([]any)
				delete(channels[0].(map[string]any), "nonClaims")
				writeReleaseManifest(t, root, manifest)
			},
		},
		{
			name:        "candidate npm registry channel with unrelated non-claim",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				manifest := releaseManifestFixture(true)
				channels := manifest["channels"].([]any)
				channels[0].(map[string]any)["nonClaims"] = []any{"This does not claim vulnerability absence."}
				writeReleaseManifest(t, root, manifest)
			},
		},
		{
			name:        "candidate npm registry channel with inverted non-claim",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				manifest := releaseManifestFixture(true)
				channels := manifest["channels"].([]any)
				channels[0].(map[string]any)["nonClaims"] = []any{"This candidate manifest proves npm registry publication, registry install authority, and consumer adoption."}
				writeReleaseManifest(t, root, manifest)
			},
		},
		{
			name:        "workflow publication with wrong trusted publisher job",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "release", "release-manifest.json"), releaseManifestFixtureWithNpmPublication("published_by_workflow", trustedPublisherFixture("npm-production", "release-metadata")))
			},
		},
		{
			name:        "mixed publication with wrong trusted publisher job",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "release", "release-manifest.json"), releaseManifestFixtureWithNpmPublication("mixed", trustedPublisherFixture("npm-production", "release-metadata")))
			},
		},
		{
			name:        "existing byte match with trusted publisher identity",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "release", "release-manifest.json"), releaseManifestFixtureWithNpmPublication("existing_byte_match", trustedPublisherFixture("npm-production", "publish")))
			},
		},
		{
			name:        "unknown publication mode",
			criterionID: "proofkit.release_closeout.channel_scope",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "release", "release-manifest.json"), releaseManifestFixtureWithNpmPublication("published-by-workflow", nil))
			},
		},
		{
			name:        "invalid self evidence JSON",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				writeFile(t, filepath.Join(root, "artifacts", "proofkit", "coverage-metrics.json"), "{")
			},
		},
		{
			name:        "candidate-only coverage v1",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				record["artifactKind"] = "proofkit.coverage-metrics.v1"
				record["schemaVersion"] = 1
				writeJSON(t, filepath.Join(root, filepath.FromSlash(coverageMetricsPath)), record)
			},
		},
		{
			name:        "missing command oracle diagnostic",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				if err := os.Remove(filepath.Join(root, filepath.FromSlash(commandOracleRecordPath))); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:        "command oracle digest substitution",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := readJSONMap(t, filepath.Join(root, filepath.FromSlash(coverageMetricsPath)))
				record["commandRoutes"].(map[string]any)["commandOracleRecordDigest"] = strings.Repeat("9", 64)
				writeJSON(t, filepath.Join(root, filepath.FromSlash(coverageMetricsPath)), record)
			},
		},
		{
			name:        "command oracle source identity substitution",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := readJSONMap(t, filepath.Join(root, filepath.FromSlash(commandOracleRecordPath)))
				record["sourceSnapshotDigest"] = strings.Repeat("9", 64)
				writeJSON(t, filepath.Join(root, filepath.FromSlash(commandOracleRecordPath)), record)
			},
		},
		{
			name:        "self evidence report with unrelated passed rule",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-proof-receipt-admission-report.json"), selfEvidenceReportFixture("proofkit.proof-receipt-admission", "proofkit.self-hosting.proof-receipts", "proofkit.unrelated.accepted"))
			},
		},
		{
			name:        "self evidence report with hidden failed rule",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				report := selfEvidenceReportFixture("proofkit.proof-receipt-admission", "proofkit.self-hosting.proof-receipts", "proofkit.proof-receipt-admission.boundary", "proofkit.proof-receipt-admission.receipts")
				report["ruleResults"] = append(report["ruleResults"].([]any), map[string]any{"ruleId": "proofkit.proof-receipt-admission.extra", "status": "failed"})
				report["summary"].(map[string]any)["failureCount"] = 1
				report["diagnostics"] = []any{map[string]any{"key": "failures", "value": []any{"extra failure"}}}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-proof-receipt-admission-report.json"), report)
			},
		},
		{
			name:        "self evidence report with non-binding summary",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				report := selfEvidenceReportFixture("proofkit.proof-receipt-admission", "proofkit.self-hosting.proof-receipts", "proofkit.proof-receipt-admission.boundary", "proofkit.proof-receipt-admission.receipts")
				report["summary"] = map[string]any{"ok": true}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-proof-receipt-admission-report.json"), report)
			},
		},
		{
			name:        "self evidence coverage dead zone",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				record["deadZones"] = map[string]any{
					"bindingWithoutRequirementIds":  []any{},
					"requirementWithoutBindingIds":  []any{"REQ-BOGUS"},
					"scenarioWithoutCommandIds":     []any{},
					"scenarioWithoutRequirementIds": []any{},
				}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with non-binding dead zones",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				record["deadZones"] = map[string]any{"notADeadZone": []any{}}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with non-binding command routes",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				record["commandRoutes"] = map[string]any{"notADefect": []any{}}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage missing producer command route count",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				routes := record["commandRoutes"].(map[string]any)
				delete(routes, "admittedInventoryEntryCount")
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with contradictory declared route count",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				routes := record["commandRoutes"].(map[string]any)
				routes["commandWithoutDeclaredSemanticFalsifierRouteCount"] = 0
				routes["commandsWithoutDeclaredSemanticFalsifierRoute"] = []any{"ghost"}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with substituted declared-route command identity",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				record["commandRoutes"].(map[string]any)["commandsWithoutDeclaredSemanticFalsifierRoute"] = []any{"proofkit.command.substituted"}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with coordinated alien command inventories",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				alien := []any{"proofkit.command.substituted"}
				record["cliContract"].(map[string]any)["commands"] = alien
				routes := record["commandRoutes"].(map[string]any)
				routes["commands"] = alien
				routes["commandsWithoutDeclaredSemanticFalsifierRoute"] = alien
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with inventory route count mismatch",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				record["commandRoutes"].(map[string]any)["admittedInventoryEntryCount"] = 2
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with candidate projection mismatch",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				record["commandRoutes"].(map[string]any)["proofRouteCandidateInventoryEntryCount"] = 0
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with impossible inventory class partition",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				routes := record["commandRoutes"].(map[string]any)
				routes["routeSmokeCount"] = 1
				routes["declaredSemanticFalsifierRouteEntryCount"] = 1
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with declared entries unavailable from producer",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				record["commandRoutes"].(map[string]any)["declaredSemanticFalsifierRouteEntryCount"] = 1
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with candidate routes unable to cover commands",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				routes := record["commandRoutes"].(map[string]any)
				routes["commandCount"] = 2
				routes["commands"] = []any{"proofkit.command.a", "proofkit.command.b"}
				routes["commandWithoutDeclaredSemanticFalsifierRouteCount"] = 2
				routes["commandsWithoutDeclaredSemanticFalsifierRoute"] = []any{"proofkit.command.a", "proofkit.command.b"}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with overflow-shaped route partition",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				maximum := int(^uint(0) >> 1)
				record := coverageMetricsFixture()
				routes := record["commandRoutes"].(map[string]any)
				routes["admittedInventoryEntryCount"] = maximum
				routes["routeCount"] = maximum
				routes["routeSmokeCount"] = maximum
				routes["proofRouteCandidateInventoryEntryCount"] = maximum
				routes["proofRouteCandidateRouteCount"] = maximum
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with candidate routes above total routes",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				routes := record["commandRoutes"].(map[string]any)
				routes["proofRouteCandidateRouteCount"] = 2
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with incomplete declared route missing set",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				routes := record["commandRoutes"].(map[string]any)
				routes["commandWithoutDeclaredSemanticFalsifierRouteCount"] = 0
				routes["commandsWithoutDeclaredSemanticFalsifierRoute"] = []any{}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with missing declared routes above command count",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				routes := record["commandRoutes"].(map[string]any)
				routes["commandCount"] = 1
				routes["commands"] = []any{"proofkit.command.a"}
				routes["commandWithoutDeclaredSemanticFalsifierRouteCount"] = 2
				routes["commandsWithoutDeclaredSemanticFalsifierRoute"] = []any{"proofkit.command.a", "proofkit.command.b"}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with duplicate missing declared route ids",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				routes := record["commandRoutes"].(map[string]any)
				routes["commandCount"] = 2
				routes["commands"] = []any{"proofkit.command.a", "proofkit.command.b"}
				routes["commandWithoutDeclaredSemanticFalsifierRouteCount"] = 2
				routes["commandsWithoutDeclaredSemanticFalsifierRoute"] = []any{"proofkit.command.a", "proofkit.command.a"}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence coverage with unsorted missing declared route ids",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				record := coverageMetricsFixture()
				routes := record["commandRoutes"].(map[string]any)
				routes["commandCount"] = 2
				routes["commands"] = []any{"proofkit.command.a", "proofkit.command.b"}
				routes["commandWithoutDeclaredSemanticFalsifierRouteCount"] = 2
				routes["commandsWithoutDeclaredSemanticFalsifierRoute"] = []any{"proofkit.command.b", "proofkit.command.a"}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), record)
			},
		},
		{
			name:        "self evidence arbitrary receipt object",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-proof-receipts.json"), map[string]any{
					"receiptSetId":  "proofkit.self-hosting.proof-receipts",
					"schemaVersion": 1,
					"receipts":      []any{map[string]any{"anything": true}},
					"nonClaims":     []any{"Self-hosting receipts are local advisory evidence."},
				})
			},
		},
		{
			name:        "self evidence spec bundle with merge required receipt",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				bundle := specProofBundleFixture(readPackageArtifactExecutionFixture(t, root))
				bundle["mergeRequiredReceiptIds"] = []any{"receipt.local.package-artifact"}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json"), bundle)
			},
		},
		{
			name:        "self evidence spec bundle with failed receipt admission child",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				bundle := specProofBundleFixture(readPackageArtifactExecutionFixture(t, root))
				receiptAdmission := bundle["receiptAdmission"].(map[string]any)
				receiptAdmission["failures"] = []any{"child failed"}
				receiptAdmission["report"] = selfEvidenceReportFixture("proofkit.proof-receipt-admission", "proofkit.self-hosting.proof-receipts", "proofkit.proof-receipt-admission.boundary", "proofkit.proof-receipt-admission.receipts")
				receiptAdmission["report"].(map[string]any)["ruleResults"] = []any{map[string]any{"ruleId": "proofkit.proof-receipt-admission.boundary", "status": "failed"}}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json"), bundle)
			},
		},
		{
			name:        "self evidence spec bundle with arbitrary nested maps",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json"), map[string]any{
					"bundleId":                 "proofkit.self-hosting.spec-proof-bundle",
					"schemaVersion":            1,
					"mergeRequiredReceiptIds":  []any{},
					"receiptAdmission":         map[string]any{"exitCode": 0},
					"receiptProducerAdmission": map[string]any{"exitCode": 0},
					"requirementBindings":      map[string]any{"bindingCount": 1},
					"witnessPlan":              map[string]any{"commandCount": 1},
					"nonClaims":                []any{"Self-hosting bundle is local advisory evidence."},
				})
			},
		},
		{
			name:        "self evidence spec bundle with arbitrary binding records",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				bundle := specProofBundleFixture(readPackageArtifactExecutionFixture(t, root))
				bindings := bundle["requirementBindings"].(map[string]any)
				bindings["requirements"] = []any{map[string]any{"anything": true}}
				bindings["bindings"] = []any{map[string]any{"anything": true}}
				bindings["witnessCommands"] = []any{map[string]any{"anything": true}}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json"), bundle)
			},
		},
		{
			name:        "self evidence spec bundle with arbitrary witness plan records",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				bundle := specProofBundleFixture(readPackageArtifactExecutionFixture(t, root))
				plan := bundle["witnessPlan"].(map[string]any)
				plan["commands"] = []any{map[string]any{"anything": true}}
				plan["policies"] = []any{map[string]any{"anything": true}}
				plan["vocabulary"] = map[string]any{"anything": true}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json"), bundle)
			},
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			root := completeFixture(t)
			item.mutate(root)

			input, err := buildInput(root)
			if err != nil {
				t.Fatalf("buildInput() error = %v", err)
			}
			assertCriterionInventory(t, input)
			assertCriterionStatus(t, input, item.criterionID, "missing_evidence")
			assertCloseoutOutcome(t, input, 1, "failed")
			assertFailedRule(t, input, item.criterionID)
		})
	}
}

func TestCommandRouteMetricsProducerReachabilityMatchesExactProducerPartition(t *testing.T) {
	routes := producerReachableCommandRouteMetricsFixture()
	expectedCommands := producerReachableCLIContractCommands()
	if !commandRouteMetricsProducerReachable(routes, expectedCommands) {
		t.Fatal("producer-reachable route partition was rejected")
	}
	mutations := []struct {
		name   string
		mutate func(*coverageCommandRouteMetrics)
	}{
		{name: "inventory route mismatch", mutate: func(value *coverageCommandRouteMetrics) { value.AdmittedInventoryEntryCount = testIntPointer(4) }},
		{name: "missing command inventory", mutate: func(value *coverageCommandRouteMetrics) { value.Commands = nil }},
		{name: "source contract mismatch", mutate: func(value *coverageCommandRouteMetrics) {
			commands := []string{"proofkit.cli.a", "proofkit.cli.c"}
			value.Commands = &commands
			value.CommandsWithoutDeclaredSemanticFalsifierRoute = &commands
		}},
		{name: "missing candidate count", mutate: func(value *coverageCommandRouteMetrics) { value.CommandWithoutProofRouteCandidateCount = nil }},
		{name: "missing declared command identities", mutate: func(value *coverageCommandRouteMetrics) { value.CommandsWithoutDeclaredSemanticFalsifierRoute = nil }},
		{name: "candidate projection mismatch", mutate: func(value *coverageCommandRouteMetrics) {
			value.ProofRouteCandidateInventoryEntryCount = testIntPointer(1)
		}},
		{name: "route partition mismatch", mutate: func(value *coverageCommandRouteMetrics) { value.RouteSmokeCount = testIntPointer(2) }},
		{name: "unreachable declared entry", mutate: func(value *coverageCommandRouteMetrics) {
			value.DeclaredSemanticFalsifierRouteEntryCount = testIntPointer(1)
		}},
		{name: "declared missing partition mismatch", mutate: func(value *coverageCommandRouteMetrics) {
			value.CommandWithoutDeclaredSemanticFalsifierRouteCount = testIntPointer(1)
		}},
		{name: "declared missing command identity mismatch", mutate: func(value *coverageCommandRouteMetrics) {
			commands := []string{"arbitrary.a", "arbitrary.z"}
			value.CommandsWithoutDeclaredSemanticFalsifierRoute = &commands
		}},
		{name: "candidate route cannot cover commands", mutate: func(value *coverageCommandRouteMetrics) { value.CommandCount = testIntPointer(3) }},
		{name: "overflow-shaped counts", mutate: func(value *coverageCommandRouteMetrics) {
			maximum := int(^uint(0) >> 1)
			value.AdmittedInventoryEntryCount = testIntPointer(maximum)
			value.RouteCount = testIntPointer(maximum)
			value.RouteSmokeCount = testIntPointer(maximum)
			value.ProofRouteCandidateInventoryEntryCount = testIntPointer(maximum)
			value.ProofRouteCandidateRouteCount = testIntPointer(maximum)
		}},
	}
	for _, item := range mutations {
		t.Run(item.name, func(t *testing.T) {
			mutated := producerReachableCommandRouteMetricsFixture()
			item.mutate(&mutated)
			if commandRouteMetricsProducerReachable(mutated, expectedCommands) {
				t.Fatal("producer-impossible command-route metrics were admitted")
			}
		})
	}
}

func producerReachableCLIContractCommands() []string {
	return []string{"proofkit.cli.a", "proofkit.cli.b"}
}

func producerReachableCommandRouteMetricsFixture() coverageCommandRouteMetrics {
	empty := []string{}
	missingDeclared := []string{"proofkit.cli.a", "proofkit.cli.b"}
	commands := []string{"proofkit.cli.a", "proofkit.cli.b"}
	return coverageCommandRouteMetrics{
		AdmittedInventoryEntryCount:                        testIntPointer(3),
		CommandCount:                                       testIntPointer(2),
		Commands:                                           &commands,
		CommandWithoutProofRouteCandidateCount:             testIntPointer(0),
		CommandsWithoutProofRouteCandidate:                 &empty,
		ContractOnlyCommandCount:                           testIntPointer(0),
		ContractOnlyCommands:                               &empty,
		CommandWithoutDeclaredSemanticFalsifierRouteCount:  testIntPointer(2),
		CommandsWithoutDeclaredSemanticFalsifierRoute:      &missingDeclared,
		RouteCount:                                         testIntPointer(3),
		RouteOnlyCommandCount:                              testIntPointer(0),
		RouteOnlyCommands:                                  &empty,
		RouteSmokeCount:                                    testIntPointer(1),
		ProofRouteCandidateInventoryEntryCount:             testIntPointer(2),
		ProofRouteCandidateRouteCount:                      testIntPointer(2),
		DeclaredSemanticFalsifierRouteEntryCount:           testIntPointer(0),
		UnknownProofRouteCandidateRefCount:                 testIntPointer(0),
		UnknownProofRouteCandidateRefs:                     &empty,
		UnknownDeclaredSemanticRouteCommandRefCount:        testIntPointer(0),
		UnknownDeclaredSemanticRouteCommandRefs:            &empty,
		CommandOracleCandidateSetDigest:                    strings.Repeat("1", 64),
		CommandOracleCounterfeitCorpusDigest:               strings.Repeat("2", 64),
		CommandOracleRecordDigest:                          strings.Repeat("3", 64),
		CommandOracleSourceSnapshotDigest:                  strings.Repeat("4", 64),
		CommandWithoutExecutionBackedSemanticRouteCount:    testIntPointer(0),
		CommandsWithoutExecutionBackedSemanticRoute:        &empty,
		ExecutionBackedSemanticRouteEntryCount:             testIntPointer(2),
		UnknownExecutionBackedSemanticRouteCommandRefCount: testIntPointer(0),
		UnknownExecutionBackedSemanticRouteCommandRefs:     &empty,
	}
}

func testIntPointer(value int) *int {
	return &value
}

func TestBuildInputAdmitsWorkflowPublicationTrustedPublisherIdentity(t *testing.T) {
	root := completeFixture(t)
	writeReleaseManifest(t, root, releaseManifestFixtureWithNpmPublication("published_by_workflow", trustedPublisherFixture("npm-production", "publish")))
	writeLocalSelfEvidence(t, root, writePackageArtifactExecutionFixture(t, root))

	input, err := buildInput(root)
	if err != nil {
		t.Fatalf("buildInput() error = %v", err)
	}
	assertCriterionStatus(t, input, "proofkit.release_closeout.channel_scope", "satisfied")
	assertCloseoutOutcome(t, input, 0, "passed")
}

func TestBuildInputAdmitsMixedPublicationTrustedPublisherIdentity(t *testing.T) {
	root := completeFixture(t)
	writeReleaseManifest(t, root, releaseManifestFixtureWithNpmPublication("mixed", trustedPublisherFixture("npm-production", "publish")))
	writeLocalSelfEvidence(t, root, writePackageArtifactExecutionFixture(t, root))

	input, err := buildInput(root)
	if err != nil {
		t.Fatalf("buildInput() error = %v", err)
	}
	assertCriterionStatus(t, input, "proofkit.release_closeout.channel_scope", "satisfied")
	assertCloseoutOutcome(t, input, 0, "passed")
}

func TestRunWritesCompletionCriteriaJSON(t *testing.T) {
	root := completeFixture(t)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(old); err != nil {
			t.Fatal(err)
		}
	}()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(&out); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	var decoded completionInput
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("run() JSON error = %v", err)
	}
	if decoded.CompletionID != completionID {
		t.Fatalf("completionId=%q, want %q", decoded.CompletionID, completionID)
	}
	assertCriterionInventory(t, decoded)
	assertCloseoutOutcome(t, decoded, 0, "passed")
}

func TestSelfEvidenceRejectsArbitraryValidJSON(t *testing.T) {
	root := completeFixture(t)
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-proof-receipt-admission-report.json"), map[string]any{"ok": true})

	input, err := buildInput(root)
	if err != nil {
		t.Fatalf("buildInput() error = %v", err)
	}
	assertCriterionStatus(t, input, "proofkit.release_closeout.self_evidence", "missing_evidence")
	assertCloseoutOutcome(t, input, 1, "failed")
}

func TestSelfEvidenceRejectsProducerUnreachableCommandOracleRef(t *testing.T) {
	root := completeFixture(t)
	evidence, err := commandoracle.ReadDiagnostic(root)
	if err != nil {
		t.Fatal(err)
	}
	record := evidence.Record
	record.Entries = append([]commandoracle.JoinedEntry(nil), record.Entries...)
	record.Entries[0].Candidate.CommandRef = "proofkit.cli.counterfeit.command"
	candidates := make([]app.CommandCoverageOracleCandidate, 0, len(record.Entries))
	for _, entry := range record.Entries {
		candidates = append(candidates, entry.Candidate)
	}
	record.CandidateSetDigest, err = commandoracle.CandidateSetDigest(candidates)
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := commandoracle.EvidenceForRecord(record)
	if err != nil {
		t.Fatalf("counterfeit oracle must remain internally valid: %v", err)
	}
	if err := commandoracle.WriteDiagnostic(root, mutated); err != nil {
		t.Fatal(err)
	}
	coveragePath := filepath.Join(root, filepath.FromSlash(coverageMetricsPath))
	coverage := readJSONMap(t, coveragePath)
	routes := coverage["commandRoutes"].(map[string]any)
	routes["commandOracleCandidateSetDigest"] = mutated.Record.CandidateSetDigest
	routes["commandOracleRecordDigest"] = mutated.RecordDigest
	writeJSON(t, coveragePath, coverage)

	input, err := buildInput(root)
	if err != nil {
		t.Fatal(err)
	}
	assertCriterionStatus(t, input, "proofkit.release_closeout.self_evidence", "missing_evidence")
}

func TestSelfEvidenceInvokesCurrentCommandOracleOwner(t *testing.T) {
	root := completeFixture(t)
	previous := commandOracleValidateCurrent
	called := false
	commandOracleValidateCurrent = func(_ context.Context, gotRoot string, evidence commandoracle.Evidence) error {
		called = true
		if gotRoot != root || evidence.Record.CommandID != commandoracle.CommandID {
			t.Fatalf("current command oracle owner received root=%q record=%#v", gotRoot, evidence.Record)
		}
		return fmt.Errorf("counterfeit currentness failure")
	}
	t.Cleanup(func() { commandOracleValidateCurrent = previous })

	input, err := buildInput(root)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("release closeout did not invoke the current command oracle owner")
	}
	assertCriterionStatus(t, input, "proofkit.release_closeout.self_evidence", "missing_evidence")
}

func TestSelfEvidenceRequiresCurrentMatchingPackageArtifactExecution(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(string)
	}{
		{
			name: "missing execution record",
			mutate: func(root string) {
				mustRemove(t, filepath.Join(root, filepath.FromSlash(packageartifactrecord.RecordPath)))
			},
		},
		{
			name: "arbitrary execution JSON",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, filepath.FromSlash(packageartifactrecord.RecordPath)), map[string]any{"ok": true})
			},
		},
		{
			name: "stale execution record",
			mutate: func(root string) {
				writeFile(t, filepath.Join(root, "source.txt"), "source-v2\n")
			},
		},
		{
			name: "receipt execution mismatch",
			mutate: func(root string) {
				record := readPackageArtifactExecutionFixture(t, root)
				record.StartedAt = "2026-07-01T09:59:59Z"
				if err := packageartifactrecord.Write(root, record); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			root := completeFixture(t)
			item.mutate(root)
			input, err := buildInput(root)
			if err != nil {
				t.Fatalf("buildInput() error = %v", err)
			}
			assertCriterionStatus(t, input, "proofkit.release_closeout.self_evidence", "missing_evidence")
			assertCloseoutOutcome(t, input, 1, "failed")
		})
	}
}

func TestSelfEvidenceBindsReceiptFieldsToPackageArtifactExecution(t *testing.T) {
	cases := []struct {
		field string
		value any
	}{
		{field: "sourceRevision", value: "different-revision"},
		{field: "startedAt", value: "2026-07-01T09:59:59Z"},
		{field: "finishedAt", value: "2026-07-01T10:00:02Z"},
		{field: "commandDigest", value: testDigest("different-command")},
		{field: "environmentDigest", value: testDigest("different-environment")},
		{field: "toolchainDigest", value: testDigest("different-toolchain")},
		{field: "dependencyDigest", value: testDigest("different-dependency")},
		{field: "preconditionDigest", value: testDigest("different-precondition")},
		{field: "proofBindingDigest", value: testDigest("different-proof-binding")},
		{field: "witnessSelectorDigest", value: testDigest("different-witness-selector")},
	}
	for _, item := range cases {
		t.Run(item.field, func(t *testing.T) {
			root := completeFixture(t)
			mutateSelfEvidenceReceiptField(t, root, item.field, item.value)
			input, err := buildInput(root)
			if err != nil {
				t.Fatalf("buildInput() error = %v", err)
			}
			assertCriterionStatus(t, input, "proofkit.release_closeout.self_evidence", "missing_evidence")
		})
	}
}

func TestSelfEvidenceRejectsLossyReceiptProjectionCollisions(t *testing.T) {
	cases := []struct {
		field string
		value any
	}{
		{field: "runnerIdentity", value: "local.other-runner"},
		{field: "lockfileDigest", value: testDigest("different-lockfile")},
	}
	for _, item := range cases {
		t.Run(item.field, func(t *testing.T) {
			root := completeFixture(t)
			receiptsPath := filepath.Join(root, filepath.FromSlash(proofReceiptsPath))
			receiptSet := readJSONMap(t, receiptsPath)
			receiptSet["receipts"].([]any)[0].(map[string]any)[item.field] = item.value
			writeJSON(t, receiptsPath, receiptSet)
			writeOwnerSelfEvidenceReports(t, root)

			input, err := buildInput(root)
			if err != nil {
				t.Fatalf("buildInput() error = %v", err)
			}
			assertCriterionStatus(t, input, "proofkit.release_closeout.self_evidence", "missing_evidence")
		})
	}
}

func TestSelfEvidenceRejectsTagOnlyJSONStubs(t *testing.T) {
	root := completeFixture(t)
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-proof-receipt-admission-report.json"), map[string]any{
		"reportId":      "proofkit.self-hosting.proof-receipts",
		"reportKind":    "proofkit.proof-receipt-admission",
		"schemaVersion": 1,
		"state":         "passed",
	})

	input, err := buildInput(root)
	if err != nil {
		t.Fatalf("buildInput() error = %v", err)
	}
	assertCriterionStatus(t, input, "proofkit.release_closeout.self_evidence", "missing_evidence")
	assertCloseoutOutcome(t, input, 1, "failed")
}

func TestSelfEvidenceRejectsReportNotEqualToOwnerProjection(t *testing.T) {
	root := completeFixture(t)
	reportPath := filepath.Join(root, filepath.FromSlash(proofReceiptReportPath))
	record := readJSONMap(t, reportPath)
	record["diagnostics"] = []any{"malformed diagnostic"}
	record["nonClaims"] = []any{"This report approves merge and production readiness."}
	writeJSON(t, reportPath, record)
	input, err := buildInput(root)
	if err != nil {
		t.Fatalf("buildInput() error = %v", err)
	}
	assertCriterionStatus(t, input, "proofkit.release_closeout.self_evidence", "missing_evidence")
}

func TestSelfEvidenceBindsCoverageProvenanceToExecution(t *testing.T) {
	for _, field := range []string{"generatedAt", "producerCommandId", "sourceRevision", "sourceSnapshotDigest"} {
		t.Run(field, func(t *testing.T) {
			root := completeFixture(t)
			path := filepath.Join(root, filepath.FromSlash(coverageMetricsPath))
			record := readJSONMap(t, path)
			record["provenance"].(map[string]any)[field] = "mismatched"
			writeJSON(t, path, record)
			input, err := buildInput(root)
			if err != nil {
				t.Fatalf("buildInput() error = %v", err)
			}
			assertCriterionStatus(t, input, "proofkit.release_closeout.self_evidence", "missing_evidence")
		})
	}
}

func TestSelfEvidenceRejectsReceiptRejectedByReceiptOwner(t *testing.T) {
	root := completeFixture(t)
	receiptSetPath := filepath.Join(root, "artifacts/proofkit/self-hosting-proof-receipts.json")
	receiptSet := map[string]any{
		"receiptSetId":  "proofkit.self-hosting.proof-receipts",
		"schemaVersion": 1,
		"receipts":      []any{proofReceiptFixture(readPackageArtifactExecutionFixture(t, root))},
		"nonClaims":     []any{"Self-hosting receipts are local advisory evidence."},
	}
	delete(receiptSet["receipts"].([]any)[0].(map[string]any), "sourceRevision")
	writeJSON(t, receiptSetPath, receiptSet)

	input, err := buildInput(root)
	if err != nil {
		t.Fatalf("buildInput() error = %v", err)
	}
	assertCriterionStatus(t, input, "proofkit.release_closeout.self_evidence", "missing_evidence")
}

func mutateSelfEvidenceReceiptField(t *testing.T, root string, field string, value any) {
	t.Helper()
	receiptsPath := filepath.Join(root, filepath.FromSlash(proofReceiptsPath))
	receiptSet := readJSONMap(t, receiptsPath)
	receiptSet["receipts"].([]any)[0].(map[string]any)[field] = value
	writeJSON(t, receiptsPath, receiptSet)

	bundlePath := filepath.Join(root, filepath.FromSlash(specProofBundlePath))
	bundle := readJSONMap(t, bundlePath)
	receiptAdmission := bundle["receiptAdmission"].(map[string]any)
	receiptAdmission["receipts"].([]any)[0].(map[string]any)[field] = value
	refreshBundleChildReports(bundle)
	writeJSON(t, bundlePath, bundle)
	writeOwnerSelfEvidenceReports(t, root)
}

func completeFixture(t *testing.T) string {
	t.Helper()
	completeFixtureBaseOnce.Do(func() {
		completeFixtureBaseRoot, completeFixtureBaseErr = os.MkdirTemp("", "proofkit-release-closeout-fixture-")
		if completeFixtureBaseErr != nil {
			return
		}
		populateCompleteFixture(t, completeFixtureBaseRoot)
	})
	if completeFixtureBaseErr != nil {
		t.Fatalf("create complete fixture base: %v", completeFixtureBaseErr)
	}
	root := t.TempDir()
	if err := os.CopyFS(root, os.DirFS(completeFixtureBaseRoot)); err != nil {
		t.Fatalf("copy complete fixture base: %v", err)
	}
	return root
}

func populateCompleteFixture(t *testing.T, root string) {
	t.Helper()
	runFixtureGit(t, root, "init")
	runFixtureGit(t, root, "config", "user.email", "proofkit@example.invalid")
	runFixtureGit(t, root, "config", "user.name", "Proofkit Test")
	writeFile(t, filepath.Join(root, ".gitignore"), "artifacts/\n")
	writeFile(t, filepath.Join(root, "go.mod"), "module example.invalid/proofkit-fixture\n\ngo 1.24\n")
	writeFile(t, filepath.Join(root, "go.sum"), "")
	writeJSON(t, filepath.Join(root, "proofkit", "requirement-bindings.json"), map[string]any{"schemaVersion": 1})
	writeJSON(t, filepath.Join(root, "proofkit", "witness-plan.json"), map[string]any{"schemaVersion": 1})
	writeJSON(t, filepath.Join(root, filepath.FromSlash(cliContractPath)), map[string]any{
		"commands": []any{map[string]any{"command": "coverage.command"}},
	})
	writeFile(t, filepath.Join(root, "source.txt"), "source-v1\n")
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{
		"name":       testNPMPackageName,
		"version":    "1.2.3",
		"repository": map[string]any{"url": "git+https://github.com/research-engineering/agentic-proofkit.git"},
	})
	writeJSON(t, filepath.Join(root, filepath.FromSlash(releasechange.RecordPath)), releaseChangeRecordFixture())
	runFixtureGit(t, root, "add", ".gitignore", "go.mod", "go.sum", "package.json", "proofkit", "release", "source.txt")
	runFixtureGit(t, root, "commit", "-m", "fixture")
	writeNPMArtifact(t, root, testNPMTarballName, []byte("package"))
	wheelSHA256, binarySHA256 := writePythonWheelFixture(t, root)
	writeJSON(t, filepath.Join(root, "artifacts", "pypi", "python-packages.json"), map[string]any{
		"packageName":    testPythonPackageName,
		"packageVersion": "1.2.3",
		"packages": []any{
			map[string]any{"binarySha256": binarySHA256, "filename": testPythonWheelName, "name": testPythonPackageName, "sha256": wheelSHA256, "version": "1.2.3"},
		},
	})
	changeRecord, err := releasechange.Read(filepath.Join(root, filepath.FromSlash(releasechange.RecordPath)))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "artifacts", "release", "release-notes.md"), releasechange.RenderMarkdown(changeRecord, testNPMPackageName, testPythonPackageName, false))
	writeJSON(t, filepath.Join(root, "artifacts", "release", "sbom.cdx.json"), map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6"})
	writeReleaseManifest(t, root, releaseManifestFixture(true))
	writeChecksumFile(t, root, "artifacts/release/checksums.sha256", []string{
		"artifacts/package/" + testNPMTarballName,
		"artifacts/pypi/" + testPythonWheelName,
		"artifacts/release/sbom.cdx.json",
	})
	writeChecksumFile(t, root, "artifacts/release/sbom-subjects.sha256", []string{
		"artifacts/package/" + testNPMTarballName,
		"artifacts/pypi/" + testPythonWheelName,
	})
	execution := writePackageArtifactExecutionFixture(t, root)
	writeLocalSelfEvidence(t, root, execution)
}

func writePythonWheelFixture(t *testing.T, root string) (string, string) {
	t.Helper()
	path := filepath.Join(root, "artifacts", "pypi", testPythonWheelName)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	wheel := zip.NewWriter(file)
	header := &zip.FileHeader{Name: pythonWheelBinaryEntry, Method: zip.Store}
	header.SetMode(0o755)
	member, err := wheel.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte("fixture-binary")
	if _, err := member.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := wheel.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wheelDigest := sha256.Sum256(content)
	binaryDigest := sha256.Sum256(binary)
	return hex.EncodeToString(wheelDigest[:]), hex.EncodeToString(binaryDigest[:])
}

func releaseChangeRecordFixture() map[string]any {
	return map[string]any{
		"additions":            []any{map[string]any{"changeId": "proofkit.release.fixture", "summary": "Exercise release change projection."}},
		"breakingChanges":      []any{},
		"changeClass":          "compatible",
		"knownLimitations":     []any{"The fixture does not prove registry publication."},
		"migration":            map[string]any{"required": false, "steps": []any{}},
		"platformRequirements": []any{"Use a supported fixture platform."},
		"previousVersion":      "1.2.2",
		"rollback":             map[string]any{"strategy": "previous_admitted_version"},
		"schemaVersion":        2,
		"version":              "1.2.3",
	}
}

func writeLocalSelfEvidence(t *testing.T, root string, execution packageartifactrecord.Record) {
	t.Helper()
	writeJSON(t, filepath.Join(root, filepath.FromSlash(ciProvenancePath)), map[string]any{
		"ciTrustInputs":  map[string]any{"githubActions": false},
		"generatedAt":    "2026-07-01T10:00:02Z",
		"sourceRevision": execution.SourceRevision,
	})
	oracle := commandOracleFixture(execution)
	if err := commandoracle.WriteDiagnostic(root, oracle); err != nil {
		t.Fatal(err)
	}
	coverage := coverageMetricsFixture()
	coverageRoutes := coverage["commandRoutes"].(map[string]any)
	coverageRoutes["commandOracleCandidateSetDigest"] = oracle.Record.CandidateSetDigest
	coverageRoutes["commandOracleCounterfeitCorpusDigest"] = oracle.Record.CounterfeitCorpusDigest
	coverageRoutes["commandOracleRecordDigest"] = oracle.RecordDigest
	coverageRoutes["commandOracleSourceSnapshotDigest"] = execution.SourceSnapshotDigest
	coverage["provenance"] = coverageMetricsProvenanceFixture(execution)
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), coverage)
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-proof-receipt-admission-report.json"), selfEvidenceReportFixture("proofkit.proof-receipt-admission", "proofkit.self-hosting.proof-receipts", "proofkit.proof-receipt-admission.boundary", "proofkit.proof-receipt-admission.receipts"))
	receipt := proofReceiptFixture(execution)
	alignProofReceiptDigests(t, root, receipt, execution)
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-proof-receipts.json"), map[string]any{
		"receiptSetId":  "proofkit.self-hosting.proof-receipts",
		"schemaVersion": 1,
		"receipts":      []any{receipt},
		"nonClaims":     []any{"Self-hosting receipts are local advisory evidence."},
	})
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-receipt-producer-admission-report.json"), selfEvidenceReportFixture("proofkit.receipt-producer-admission", "proofkit.receipt-producer-policy", "proofkit.receipt-producer-admission.boundary", "proofkit.receipt-producer-admission.coverage", "proofkit.receipt-producer-admission.receipts"))
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-receipt-producer-admission.json"), map[string]any{
		"policyId":           "proofkit.receipt-producer-policy",
		"schemaVersion":      1,
		"environmentClasses": []any{packageGateEnvironmentClass},
		"producers":          []any{receiptProducerFixture()},
		"receiptKinds":       []any{"proofkit.package-artifact"},
		"receipts":           []any{receiptProducerReceiptFixture()},
		"nonClaims":          []any{"Local receipts are advisory evidence."},
	})
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle-admission-report.json"), selfEvidenceReportFixture("proofkit.spec-proof-bundle-admission", "proofkit.self-hosting.spec-proof-bundle", "proofkit.spec-proof-bundle-admission.accepted"))
	bundle := specProofBundleFixture(execution)
	bundle["receiptAdmission"].(map[string]any)["receipts"] = []any{receipt}
	refreshBundleChildReports(bundle)
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json"), bundle)
	writeOwnerSelfEvidenceReports(t, root)
}

func writePackageArtifactExecutionFixture(t *testing.T, root string) packageartifactrecord.Record {
	t.Helper()
	revision, sourceDigest, err := packageartifactrecord.SourceSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	artifactEvidence, err := packageartifactrecord.ArtifactEvidenceSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	record := packageartifactrecord.Record{
		Argv:                   packageartifactrecord.CanonicalCommandArgv(),
		ArtifactSnapshotDigest: artifactEvidence.SnapshotDigest,
		CommandID:              packageartifactrecord.CommandID,
		EnvironmentDigest:      strings.Repeat("1", 64),
		ExecutionArgv:          packageartifactrecord.CanonicalExecutionArgv(),
		ExitCode:               0,
		FinishedAt:             "2026-07-01T10:00:01Z",
		SchemaVersion:          packageartifactrecord.SchemaVersion,
		SourceRevision:         revision,
		SourceSnapshotDigest:   sourceDigest,
		StartedAt:              "2026-07-01T10:00:00Z",
		Status:                 "passed",
		ToolchainDigest:        strings.Repeat("2", 64),
	}
	if err := packageartifactrecord.Write(root, record); err != nil {
		t.Fatal(err)
	}
	return record
}

func readPackageArtifactExecutionFixture(t *testing.T, root string) packageartifactrecord.Record {
	t.Helper()
	record, err := packageartifactrecord.Read(root)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func runFixtureGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func writeGitHubActionsSelfEvidence(t *testing.T, root string) {
	t.Helper()
	execution := readPackageArtifactExecutionFixture(t, root)
	receipt := proofReceiptFixture(execution)
	alignProofReceiptDigests(t, root, receipt, execution)
	receipt["receiptId"] = "receipt.github.actions.package-artifact"
	receipt["producerId"] = "github.actions.package"
	receipt["runnerClass"] = "github.actions.hosted"
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-proof-receipts.json"), map[string]any{
		"nonClaims":     []any{"Self-hosting receipts remain advisory evidence."},
		"receiptSetId":  "proofkit.self-hosting.proof-receipts",
		"receipts":      []any{receipt},
		"schemaVersion": 1,
	})

	producer := receiptProducerFixture()
	producer["producerId"] = "github.actions.package"
	producer["nonClaim"] = "GitHub Actions package receipts are advisory."
	producerReceipt := receiptProducerReceiptFixture()
	producerReceipt["receiptId"] = "receipt.github.actions.package-artifact"
	producerReceipt["producerId"] = "github.actions.package"
	producerReceipt["nonClaim"] = "GitHub Actions advisory receipts do not satisfy merge obligations."
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-receipt-producer-admission.json"), map[string]any{
		"environmentClasses": []any{packageGateEnvironmentClass},
		"nonClaims":          []any{"GitHub Actions receipts remain advisory."},
		"policyId":           "proofkit.receipt-producer-policy",
		"producers":          []any{producer},
		"receiptKinds":       []any{"proofkit.package-artifact"},
		"receipts":           []any{producerReceipt},
		"schemaVersion":      1,
	})

	bundle := specProofBundleFixture(execution)
	receiptAdmission := bundle["receiptAdmission"].(map[string]any)
	receiptAdmission["receipts"] = []any{receipt}
	producerAdmission := bundle["receiptProducerAdmission"].(map[string]any)
	producerAdmission["producers"] = []any{producer}
	producerAdmission["receipts"] = []any{producerReceipt}
	refreshBundleChildReports(bundle)
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json"), bundle)
	writeOwnerSelfEvidenceReports(t, root)
}

func writeOwnerSelfEvidenceReports(t *testing.T, root string) {
	t.Helper()
	proofRaw, err := readAdmittedJSON(root, proofReceiptsPath)
	if err != nil {
		t.Fatal(err)
	}
	proofReport, proofExit, err := proofreceiptadmission.Build(proofRaw)
	if err != nil || proofExit != 0 {
		t.Fatalf("build proof receipt report: exit=%d err=%v", proofExit, err)
	}
	writeJSON(t, filepath.Join(root, filepath.FromSlash(proofReceiptReportPath)), proofReport.JSONValue())

	producerRaw, err := readAdmittedJSON(root, producerPolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	producerReport, producerExit, err := receiptproduceradmission.Build(producerRaw)
	if err != nil || producerExit != 0 {
		t.Fatalf("build producer report: exit=%d err=%v", producerExit, err)
	}
	writeJSON(t, filepath.Join(root, filepath.FromSlash(producerReportPath)), producerReport.JSONValue())

	bundleRaw, err := readAdmittedJSON(root, specProofBundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundleReport, bundleExit, err := specproofbundleadmission.Build(bundleRaw)
	if err != nil || bundleExit != 0 {
		t.Fatalf("build spec proof bundle report: exit=%d err=%v", bundleExit, err)
	}
	writeJSON(t, filepath.Join(root, filepath.FromSlash(specProofBundleReportPath)), bundleReport.JSONValue())
}

func writeMixedSelfEvidenceIdentity(t *testing.T, root string) {
	t.Helper()
	execution := readPackageArtifactExecutionFixture(t, root)
	githubProducer := receiptProducerFixture()
	githubProducer["producerId"] = "github.actions.package"
	githubProducer["nonClaim"] = "GitHub Actions package receipts are advisory."
	githubProducerReceipt := receiptProducerReceiptFixture()
	githubProducerReceipt["receiptId"] = "receipt.github.actions.package-artifact"
	githubProducerReceipt["producerId"] = "github.actions.package"
	githubProducerReceipt["nonClaim"] = "GitHub Actions advisory receipts do not satisfy merge obligations."
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-receipt-producer-admission.json"), map[string]any{
		"environmentClasses": []any{packageGateEnvironmentClass},
		"nonClaims":          []any{"Mixed fixture must be rejected."},
		"policyId":           "proofkit.receipt-producer-policy",
		"producers":          []any{githubProducer},
		"receiptKinds":       []any{"proofkit.package-artifact"},
		"receipts":           []any{githubProducerReceipt},
		"schemaVersion":      1,
	})
	bundle := specProofBundleFixture(execution)
	producerAdmission := bundle["receiptProducerAdmission"].(map[string]any)
	producerAdmission["producers"] = []any{githubProducer}
	producerAdmission["receipts"] = []any{githubProducerReceipt}
	refreshBundleChildReports(bundle)
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json"), bundle)
}

func refreshBundleChildReports(bundle map[string]any) {
	proofChild := bundle["receiptAdmission"].(map[string]any)
	proofInput := map[string]any{
		"schemaVersion": json.Number("1"), "receiptSetId": "proofkit.self-hosting.proof-receipts",
		"receipts": proofChild["receipts"], "nonClaims": proofChild["nonClaims"],
	}
	proofReport, proofExit, proofErr := proofreceiptadmission.Build(decodedFixture(proofInput))
	if proofErr != nil || proofExit != 0 {
		panic(fmt.Sprintf("refresh proof receipt fixture report: exit=%d err=%v", proofExit, proofErr))
	}
	proofChild["report"] = proofReport.JSONValue()

	producerChild := bundle["receiptProducerAdmission"].(map[string]any)
	producerInput := map[string]any{
		"schemaVersion": json.Number("1"), "policyId": "proofkit.receipt-producer-policy",
		"environmentClasses": producerChild["environmentClasses"], "receiptKinds": producerChild["receiptKinds"],
		"producers": producerChild["producers"], "receipts": producerChild["receipts"], "nonClaims": producerChild["nonClaims"],
	}
	producerReport, producerExit, producerErr := receiptproduceradmission.Build(decodedFixture(producerInput))
	if producerErr != nil || producerExit != 0 {
		panic(fmt.Sprintf("refresh producer fixture report: exit=%d err=%v", producerExit, producerErr))
	}
	producerChild["report"] = producerReport.JSONValue()
}

func coverageMetricsFixture() map[string]any {
	return map[string]any{
		"artifactKind":  "proofkit.coverage-metrics.v2",
		"schemaVersion": 2,
		"requirements":  map[string]any{"blocking": 1},
		"proofBindings": map[string]any{"boundRequirementCount": 1},
		"witnessPlan":   map[string]any{"commandCount": 1},
		"cliContract":   map[string]any{"commandCount": 1, "commands": []any{"coverage.command"}},
		"commandRoutes": map[string]any{
			"admittedInventoryEntryCount":                        1,
			"commandCount":                                       1,
			"commands":                                           []any{"coverage.command"},
			"commandWithoutProofRouteCandidateCount":             0,
			"commandsWithoutProofRouteCandidate":                 []any{},
			"commandWithoutDeclaredSemanticFalsifierRouteCount":  1,
			"commandsWithoutDeclaredSemanticFalsifierRoute":      []any{"coverage.command"},
			"contractOnlyCommandCount":                           0,
			"contractOnlyCommands":                               []any{},
			"routeCount":                                         1,
			"routeOnlyCommandCount":                              0,
			"routeOnlyCommands":                                  []any{},
			"routeSmokeCount":                                    0,
			"proofRouteCandidateInventoryEntryCount":             1,
			"proofRouteCandidateRouteCount":                      1,
			"declaredSemanticFalsifierRouteEntryCount":           0,
			"unknownProofRouteCandidateRefCount":                 0,
			"unknownProofRouteCandidateRefs":                     []any{},
			"unknownDeclaredSemanticRouteCommandRefCount":        0,
			"unknownDeclaredSemanticRouteCommandRefs":            []any{},
			"commandOracleCandidateSetDigest":                    strings.Repeat("1", 64),
			"commandOracleCounterfeitCorpusDigest":               strings.Repeat("2", 64),
			"commandOracleRecordDigest":                          strings.Repeat("3", 64),
			"commandOracleSourceSnapshotDigest":                  strings.Repeat("0", 64),
			"commandWithoutExecutionBackedSemanticRouteCount":    0,
			"commandsWithoutExecutionBackedSemanticRoute":        []any{},
			"executionBackedSemanticRouteEntryCount":             1,
			"unknownExecutionBackedSemanticRouteCommandRefCount": 0,
			"unknownExecutionBackedSemanticRouteCommandRefs":     []any{},
		},
		"deadZones": map[string]any{
			"bindingWithoutRequirementIds":  []any{},
			"requirementWithoutBindingIds":  []any{},
			"scenarioWithoutCommandIds":     []any{},
			"scenarioWithoutRequirementIds": []any{},
		},
		"nonClaims": []any{"Coverage metrics do not prove runtime readiness."},
		"provenance": map[string]any{
			"generatedAt":          "2026-01-01T00:00:01Z",
			"producerCommandId":    "proofkit.coverage-metrics",
			"sourceRevision":       "mismatched-source",
			"sourceSnapshotDigest": strings.Repeat("0", 64),
		},
	}
}

func commandOracleFixture(execution packageartifactrecord.Record) commandoracle.Evidence {
	candidate := app.CommandCoverageOracleCandidate{
		AssertionOracleID:        "proofkit.oracle.fixture",
		CommandRef:               "proofkit.cli.coverage.command",
		ExpectedPublicOutcome:    "Fixture command rejects its declared counterfeit input.",
		FalsificationEventID:     "proofkit.falsifier.fixture",
		NegativeCaseID:           "proofkit.negative.fixture",
		OracleKind:               "semantic_route_falsifier",
		OwnerInvariantID:         "proofkit.invariant.fixture",
		PackagePath:              "./internal/sample",
		Selector:                 "internal/sample/sample_test.go::TestFixture",
		SourceMarker:             "proofkit.command_coverage.source_oracle.v1.000000000000000000000000000000000000000000000000000000000000000000000000000001",
		SourcePath:               "internal/sample/sample_test.go",
		TestID:                   "proofkit.test.fixture",
		TestName:                 "TestFixture",
		WrongImplementationClass: "proofkit.wrong.fixture",
	}
	candidates := []app.CommandCoverageOracleCandidate{candidate}
	candidateDigest, err := commandoracle.CandidateSetDigest(candidates)
	if err != nil {
		panic(err)
	}
	record := commandoracle.Record{
		ArtifactKind:            commandoracle.ArtifactKind,
		CandidateSetDigest:      candidateDigest,
		CommandID:               commandoracle.CommandID,
		CounterfeitCorpusDigest: strings.Repeat("2", 64),
		Entries: []commandoracle.JoinedEntry{{
			Candidate:         candidate,
			ExecutionState:    "passed",
			PackageImportPath: "example.test/proofkit/internal/sample",
		}},
		ExecutionCommands:    commandoracle.ExecutionCommandsForCandidates(candidates),
		GoVersion:            runtime.Version(),
		NonClaims:            commandoracle.RecordNonClaims(),
		Platform:             runtime.GOOS + "/" + runtime.GOARCH,
		SchemaVersion:        commandoracle.SchemaVersion,
		SourceRevision:       execution.SourceRevision,
		SourceSnapshotDigest: execution.SourceSnapshotDigest,
		State:                "passed",
	}
	evidence, err := commandoracle.EvidenceForRecord(record)
	if err != nil {
		panic(err)
	}
	return evidence
}

func coverageMetricsProvenanceFixture(execution packageartifactrecord.Record) map[string]any {
	finishedAt, err := time.Parse(time.RFC3339Nano, execution.FinishedAt)
	if err != nil {
		panic(err)
	}
	return map[string]any{
		"generatedAt":          finishedAt.Add(time.Nanosecond).Format(time.RFC3339Nano),
		"producerCommandId":    "proofkit.coverage-metrics",
		"sourceRevision":       execution.SourceRevision,
		"sourceSnapshotDigest": execution.SourceSnapshotDigest,
	}
}

func writeReleaseManifest(t *testing.T, root string, manifest map[string]any) {
	t.Helper()
	writeJSON(t, filepath.Join(root, "artifacts", "release", "release-manifest.json"), manifest)
	writeChecksumFile(t, root, "artifacts/release/metadata-checksums.sha256", []string{
		"artifacts/release/release-manifest.json",
		"artifacts/release/release-notes.md",
	})
}

func selfEvidenceReportFixture(reportKind string, reportID string, ruleIDs ...string) map[string]any {
	ruleResults := make([]any, 0, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		ruleResults = append(ruleResults, map[string]any{"ruleId": ruleID, "status": "passed"})
	}
	return map[string]any{
		"diagnostics":   []any{map[string]any{"key": "failures", "value": []any{}}},
		"nonClaims":     []any{"Self-hosting report is local advisory evidence."},
		"reportId":      reportID,
		"reportKind":    reportKind,
		"ruleResults":   ruleResults,
		"schemaVersion": 1,
		"state":         "passed",
		"summary":       map[string]any{"failureCount": 0, "passedRuleCount": len(ruleResults)},
	}
}

func proofReceiptFixture(execution packageartifactrecord.Record) map[string]any {
	commandDigest, err := packageArtifactCommandDigest(execution)
	if err != nil {
		panic(err)
	}
	return map[string]any{
		"artifactRefs":           []any{map[string]any{"kind": "artifact", "path": "artifacts/package/" + testNPMTarballName, "sha256": testDigest("artifact")}},
		"commandDigest":          commandDigest,
		"dependencyDigest":       testDigest("dependency"),
		"environmentClass":       packageGateEnvironmentClass,
		"environmentDigest":      "sha256:" + execution.EnvironmentDigest,
		"evidenceRefs":           []any{"artifacts/package/npm-pack.json"},
		"exitCode":               0,
		"finishedAt":             execution.FinishedAt,
		"lockfileDigest":         nil,
		"nonClaims":              []any{"Self-hosting proof receipts do not approve merge."},
		"preconditionDigest":     testDigest("precondition"),
		"producerAdmissionClass": "advisory",
		"producerId":             "local.developer",
		"proofBindingDigest":     testDigest("binding"),
		"proofPlanId":            "proofkit.self-hosting.witness-plan",
		"provenanceRef":          "artifacts/proofkit/ci-provenance.json",
		"receiptId":              "receipt.local.package-artifact",
		"receiptKind":            "proofkit.package-artifact",
		"runnerClass":            "local",
		"runnerIdentity":         "local.developer",
		"sourceRevision":         execution.SourceRevision,
		"startedAt":              execution.StartedAt,
		"status":                 "passed",
		"toolchainDigest":        "sha256:" + execution.ToolchainDigest,
		"witnessSelectorDigest":  testDigest("selector"),
		"witnessSelectors":       []any{"REQ-PROOFKIT-PACKAGE-003"},
	}
}

func alignProofReceiptDigests(t *testing.T, root string, receipt map[string]any, execution packageartifactrecord.Record) {
	t.Helper()
	goModDigest, err := fileDigestRef(root, "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	goSumDigest, err := fileDigestRef(root, "go.sum")
	if err != nil {
		t.Fatal(err)
	}
	packageJSONDigest, err := fileDigestRef(root, "package.json")
	if err != nil {
		t.Fatal(err)
	}
	witnessPlanDigest, err := fileDigestRef(root, "proofkit/witness-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	proofBindingDigest, err := fileDigestRef(root, "proofkit/requirement-bindings.json")
	if err != nil {
		t.Fatal(err)
	}
	provenance := readJSONMap(t, filepath.Join(root, filepath.FromSlash(ciProvenancePath)))
	ciTrustInputDigest, err := digest.StableJSONSHA256Ref(provenance["ciTrustInputs"])
	if err != nil {
		t.Fatal(err)
	}
	dependencyDigest, err := digest.StableJSONSHA256Ref(map[string]any{"goModDigest": goModDigest, "goSumDigest": goSumDigest})
	if err != nil {
		t.Fatal(err)
	}
	preconditionDigest, err := digest.StableJSONSHA256Ref(map[string]any{
		"artifactSnapshotDigest": execution.ArtifactSnapshotDigest,
		"ciTrustInputDigest":     ciTrustInputDigest,
		"goModDigest":            goModDigest,
		"goSumDigest":            goSumDigest,
		"packageJsonDigest":      packageJSONDigest,
		"sourceSnapshotDigest":   execution.SourceSnapshotDigest,
		"witnessPlanDigest":      witnessPlanDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	witnessSelectorDigest, err := digest.StableJSONSHA256Ref(receipt["witnessSelectors"])
	if err != nil {
		t.Fatal(err)
	}
	receipt["dependencyDigest"] = dependencyDigest
	receipt["preconditionDigest"] = preconditionDigest
	receipt["proofBindingDigest"] = proofBindingDigest
	receipt["witnessSelectorDigest"] = witnessSelectorDigest
}

func testDigest(seed string) string {
	hexDigits := "abcdef0123456789"
	return "sha256:" + strings.Repeat(hexDigits[len(seed)%len(hexDigits):len(seed)%len(hexDigits)+1], 64)
}

func receiptProducerFixture() map[string]any {
	return map[string]any{
		"admissionLevel":     "advisory",
		"environmentClasses": []any{packageGateEnvironmentClass},
		"evidenceRefs":       []any{"AGENTS.md"},
		"nonClaim":           "Local developer receipts are advisory.",
		"owner":              "proofkit.package-boundary",
		"producerId":         "local.developer",
		"receiptKinds":       []any{"proofkit.package-artifact"},
	}
}

func receiptProducerReceiptFixture() map[string]any {
	return map[string]any{
		"artifactRefs":             []any{"artifacts/package/" + testNPMTarballName},
		"environmentClass":         packageGateEnvironmentClass,
		"evidenceRef":              "artifacts/proofkit/self-hosting-proof-receipts.json",
		"nonClaim":                 "Local advisory receipts do not satisfy merge obligations.",
		"producerId":               "local.developer",
		"provenanceRef":            "artifacts/proofkit/ci-provenance.json",
		"receiptId":                "receipt.local.package-artifact",
		"receiptKind":              "proofkit.package-artifact",
		"satisfiesMergeObligation": false,
		"status":                   "passed",
		"subjectRef":               "proofkit.package-boundary.self-hosting",
	}
}

func specProofBundleFixture(execution packageartifactrecord.Record) map[string]any {
	proofNonClaims := []any{"Proof receipt admission remains local advisory evidence."}
	proofInput := map[string]any{"schemaVersion": json.Number("1"), "receiptSetId": "proofkit.self-hosting.proof-receipts", "receipts": []any{proofReceiptFixture(execution)}, "nonClaims": proofNonClaims}
	proofReport, proofExit, proofErr := proofreceiptadmission.Build(decodedFixture(proofInput))
	if proofErr != nil || proofExit != 0 {
		panic(fmt.Sprintf("build proof receipt fixture report: exit=%d err=%v", proofExit, proofErr))
	}
	producerNonClaims := []any{"Receipt producer admission remains local advisory evidence."}
	producerInput := map[string]any{
		"schemaVersion": json.Number("1"), "policyId": "proofkit.receipt-producer-policy",
		"environmentClasses": []any{packageGateEnvironmentClass}, "receiptKinds": []any{"proofkit.package-artifact"},
		"producers": []any{receiptProducerFixture()}, "receipts": []any{receiptProducerReceiptFixture()}, "nonClaims": producerNonClaims,
	}
	producerReport, producerExit, producerErr := receiptproduceradmission.Build(decodedFixture(producerInput))
	if producerErr != nil || producerExit != 0 {
		panic(fmt.Sprintf("build producer fixture report: exit=%d err=%v", producerExit, producerErr))
	}
	return map[string]any{
		"bundleId":                "proofkit.self-hosting.spec-proof-bundle",
		"mergeRequiredReceiptIds": []any{},
		"nonClaims":               []any{"Self-hosting bundle is local advisory evidence."},
		"receiptAdmission": map[string]any{
			"exitCode":  0,
			"failures":  []any{},
			"nonClaims": proofNonClaims,
			"producers": []any{},
			"receipts":  []any{proofReceiptFixture(execution)},
			"report":    proofReport.JSONValue(),
		},
		"receiptProducerAdmission": map[string]any{
			"environmentClasses": []any{packageGateEnvironmentClass},
			"exitCode":           0,
			"failures":           []any{},
			"nonClaims":          producerNonClaims,
			"producers":          []any{receiptProducerFixture()},
			"receiptKinds":       []any{"proofkit.package-artifact"},
			"receipts":           []any{receiptProducerReceiptFixture()},
			"report":             producerReport.JSONValue(),
		},
		"requirementBindings": map[string]any{
			"bindingId": "proofkit.package-boundary.requirement-bindings",
			"bindings": []any{map[string]any{
				"commandIds":         []any{"proofkit.package-artifact"},
				"environmentClasses": []any{packageGateEnvironmentClass},
				"requirementId":      "REQ-PROOFKIT-PACKAGE-003",
				"scenarioId":         "proofkit.package-boundary.ci-receipt-anchor",
				"witnessId":          "proofkit.ci.receipt-anchor",
				"witnessKind":        "contract",
				"witnessPath":        "scripts/validate-self-hosting-receipts.go",
			}},
			"nonClaims": []any{"Requirement bindings do not execute witnesses."},
			"requirements": []any{map[string]any{
				"claimLevel":    "blocking",
				"nonClaims":     []any{"Fixture requirement does not claim publication."},
				"ownerId":       "proofkit.package-boundary",
				"proofState":    "witness_backed",
				"requirementId": "REQ-PROOFKIT-PACKAGE-003",
				"specPath":      "docs/specs/proofkit-package-boundary/requirements.v1.json",
			}},
			"schemaVersion":   1,
			"witnessCommands": []any{map[string]any{"command": "npm run package:artifact", "commandId": "proofkit.package-artifact", "environmentClass": packageGateEnvironmentClass}},
		},
		"schemaVersion": 1,
		"witnessPlan": map[string]any{
			"commands": []any{map[string]any{
				"argv":              []any{"npm", "run", "package:artifact"},
				"cachePolicy":       "disabled",
				"credentialClass":   "none",
				"cwd":               ".",
				"environment":       map[string]any{"allowlist": []any{}, "classes": []any{packageGateEnvironmentClass}, "inherit": "none"},
				"exitCodePolicy":    map[string]any{"kind": "zero", "successCodes": []any{0}},
				"expectedArtifacts": []any{map[string]any{"kind": "report", "path": "artifacts/package/npm-pack.json", "required": true}},
				"id":                "proofkit.package-artifact",
				"networkPolicy":     "none",
				"parallelGroup":     "package-artifact",
				"schemaVersion":     1,
				"timeoutMs":         600000,
			}},
			"nonClaims": []any{"Witness plan does not execute commands."},
			"policies": []any{map[string]any{
				"cacheAdmissionRefs":  []any{},
				"cancellationPolicy":  map[string]any{"graceMs": 5000, "kind": "cooperative"},
				"commandId":           "proofkit.package-artifact",
				"deterministicOutput": false,
				"exclusiveLocks":      []any{},
				"inputSelectors":      []any{"package.json"},
				"nonClaims":           []any{"Fixture witness policy does not prove execution."},
				"outputSelectors":     []any{"artifacts/package/npm-pack.json"},
				"resourceReads":       []any{"resource.proofkit.source"},
				"resourceWrites":      []any{"resource.proofkit.package-artifacts"},
				"retryPolicy":         map[string]any{"kind": "none", "maxAttempts": 1},
				"sideEffectClass":     "local_write",
				"timeoutPolicy":       map[string]any{"kind": "bounded", "timeoutMs": 600000},
			}},
			"schedulerPlanId": "proofkit.self-hosting.witness-plan",
			"schemaVersion":   1,
			"vocabulary": map[string]any{
				"artifactKinds":                 []any{"report"},
				"credentialClasses":             []any{"none"},
				"environmentClasses":            []any{packageGateEnvironmentClass},
				"environmentClassPolicies":      []any{map[string]any{"cachePolicies": []any{"disabled"}, "credentialClasses": []any{"none"}, "environmentClass": packageGateEnvironmentClass, "networkPolicies": []any{"none"}}},
				"maxTimeoutMs":                  600000,
				"nonCacheableCredentialClasses": []any{},
				"parallelGroups":                []any{"package-artifact"},
			},
		},
	}
}

func decodedFixture(value any) any {
	content, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		panic(err)
	}
	return decoded
}

func releaseManifestFixture(includePyPINonClaim bool) map[string]any {
	return releaseManifestFixtureWithPyPI("planned", includePyPINonClaim)
}

func releaseManifestFixtureWithPyPI(status string, includePyPINonClaim bool) map[string]any {
	pypi := map[string]any{
		"authorityChannel": "pypi_registry_release",
		"status":           status,
	}
	if includePyPINonClaim {
		pypi["nonClaims"] = []any{pypiPlannedNonClaim}
	}
	return map[string]any{
		"artifactKind": "proofkit.release-manifest.v1",
		"package":      map[string]any{"name": testNPMPackageName, "version": "1.2.3"},
		"channels": []any{
			map[string]any{
				"authorityChannel": "registry_release",
				"nonClaims":        []any{"Local npm package artifacts are candidate tarball evidence; they do not prove npm registry publication, registry install authority, or consumer adoption."},
				"status":           "candidate",
			},
			map[string]any{"authorityChannel": "github_release_archive", "status": "candidate"},
			map[string]any{"authorityChannel": "python_wheel_candidate", "status": "candidate"},
			pypi,
		},
		"nonClaims": []any{"Candidate manifest does not claim publication."},
	}
}

func releaseManifestFixtureWithNpmPublication(mode string, identity map[string]any) map[string]any {
	manifest := releaseManifestFixture(true)
	channels := manifest["channels"].([]any)
	npm := channels[0].(map[string]any)
	npm["status"] = "published"
	npm["publicationMode"] = mode
	if identity != nil {
		npm["trustedPublisher"] = identity
	}
	return manifest
}

func trustedPublisherFixture(environment string, job string) map[string]any {
	return map[string]any{
		"environment": environment,
		"job":         job,
		"projectName": testNPMPackageName,
		"provider":    "npm",
		"registry":    "https://registry.npmjs.org",
		"repository":  "research-engineering/agentic-proofkit",
		"workflowRef": "research-engineering/agentic-proofkit/.github/workflows/release.yml@refs/tags/v1.2.3",
	}
}

func assertCriterionStatus(t *testing.T, input completionInput, id string, status string) {
	t.Helper()
	for _, item := range input.Criteria {
		if item.CriterionID == id {
			if item.Status != status {
				t.Fatalf("%s status=%q, want %q", id, item.Status, status)
			}
			return
		}
	}
	t.Fatalf("criterion %s not found", id)
}

func assertCriterionInventory(t *testing.T, input completionInput) {
	t.Helper()
	if input.SchemaVersion != 1 {
		t.Fatalf("schemaVersion=%d, want 1", input.SchemaVersion)
	}
	want := map[string]string{
		"proofkit.release_closeout.channel_scope":                 "blocking",
		"proofkit.release_closeout.manifest_and_sbom":             "blocking",
		"proofkit.release_closeout.package_artifacts":             "blocking",
		"proofkit.release_closeout.provider_publication_advisory": "advisory",
		"proofkit.release_closeout.python_wrappers":               "blocking",
		"proofkit.release_closeout.self_evidence":                 "blocking",
	}
	if len(input.Criteria) != len(want) {
		t.Fatalf("criteria count=%d, want %d", len(input.Criteria), len(want))
	}
	for _, item := range input.Criteria {
		class, ok := want[item.CriterionID]
		if !ok {
			t.Fatalf("unexpected criterion %s", item.CriterionID)
		}
		if item.CriterionClass != class {
			t.Fatalf("%s class=%q, want %q", item.CriterionID, item.CriterionClass, class)
		}
		if item.Criterion == "" || len(item.FailsWhen) == 0 || len(item.NonClaims) == 0 {
			t.Fatalf("%s is missing criterion text, failsWhen, or nonClaims: %#v", item.CriterionID, item)
		}
		delete(want, item.CriterionID)
	}
	if len(want) != 0 {
		t.Fatalf("missing criteria: %#v", want)
	}
}

func assertCloseoutOutcome(t *testing.T, input completionInput, wantExit int, wantState string) {
	t.Helper()
	record, exitCode, err := completioncriteria.Build(toMap(t, input))
	if err != nil {
		t.Fatalf("completioncriteria.Build() error = %v", err)
	}
	if exitCode != wantExit || record.State != wantState {
		t.Fatalf("completioncriteria.Build() exit=%d state=%s, want exit=%d state=%s rules=%#v", exitCode, record.State, wantExit, wantState, record.RuleResults)
	}
}

func assertFailedRule(t *testing.T, input completionInput, criterionID string) {
	t.Helper()
	record, _, err := completioncriteria.Build(toMap(t, input))
	if err != nil {
		t.Fatalf("completioncriteria.Build() error = %v", err)
	}
	ruleID := "proofkit.completion-criteria." + criterionID
	for _, item := range record.RuleResults {
		if item.RuleID == ruleID {
			if item.Status != "failed" {
				t.Fatalf("%s status=%q, want failed", ruleID, item.Status)
			}
			return
		}
	}
	t.Fatalf("rule %s not found", ruleID)
}

func toMap(t *testing.T, input completionInput) map[string]any {
	t.Helper()
	content, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var decoded map[string]any
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func replaceDirectoryWithSymlink(t *testing.T, path string) {
	t.Helper()
	target := filepath.Join(t.TempDir(), filepath.Base(path))
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(content))
}

func readJSONMap(t *testing.T, path string) map[string]any {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	value, err := admission.DecodeJSON(file, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s must contain an object", path)
	}
	return record
}

func writeNPMArtifact(t *testing.T, root string, filename string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "artifacts", "package"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "artifacts", "package", filename), content, 0o644); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(root, "artifacts", "package", "npm-pack.json"), []any{
		map[string]any{
			"filename":  filename,
			"integrity": testNPMIntegrity(content),
			"name":      testNPMPackageName,
			"shasum":    testSHA1(content),
			"version":   "1.2.3",
		},
	})
}

func testSHA1(content []byte) string {
	sum := sha1.Sum(content)
	return hex.EncodeToString(sum[:])
}

func testNPMIntegrity(content []byte) string {
	hash := sha512.New()
	_, _ = hash.Write(content)
	return "sha512-" + base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeChecksumFile(t *testing.T, root string, path string, targetPaths []string) {
	t.Helper()
	targets := append([]string{}, targetPaths...)
	sort.Strings(targets)
	lines := make([]string, 0, len(targets))
	for _, target := range targets {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(target)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		lines = append(lines, hex.EncodeToString(sum[:])+"  "+filepath.Base(target))
	}
	writeFile(t, filepath.Join(root, filepath.FromSlash(path)), strings.Join(lines, "\n")+"\n")
}
