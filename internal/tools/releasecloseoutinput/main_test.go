package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/completioncriteria"
)

const (
	testNPMPackageName    = "@research-engineering/agentic-proofkit"
	testNPMTarballName    = "research-engineering-agentic-proofkit-1.2.3.tgz"
	testPythonPackageName = "agentic-proofkit"
	testPythonWheelName   = "agentic_proofkit-1.2.3-py3-none-any.whl"
)

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
			name:        "stale retained evidence checksums",
			criterionID: "proofkit.release_closeout.manifest_and_sbom",
			mutate: func(root string) {
				writeJSON(t, filepath.Join(root, "artifacts", "release", "github-release.json"), map[string]any{
					"tagName": "v1.2.3",
					"assets":  []any{},
				})
				writeFile(t, filepath.Join(root, "artifacts", "release", "retained-evidence-checksums.sha256"), strings.Repeat("a", 64)+"  github-release.json\n")
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
				bundle := specProofBundleFixture()
				bundle["mergeRequiredReceiptIds"] = []any{"receipt.local.package-gate"}
				writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json"), bundle)
			},
		},
		{
			name:        "self evidence spec bundle with failed receipt admission child",
			criterionID: "proofkit.release_closeout.self_evidence",
			mutate: func(root string) {
				bundle := specProofBundleFixture()
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
				bundle := specProofBundleFixture()
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
				bundle := specProofBundleFixture()
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

func TestBuildInputAdmitsWorkflowPublicationTrustedPublisherIdentity(t *testing.T) {
	root := completeFixture(t)
	writeReleaseManifest(t, root, releaseManifestFixtureWithNpmPublication("published_by_workflow", trustedPublisherFixture("npm-production", "publish")))

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

func completeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{
		"name":       testNPMPackageName,
		"version":    "1.2.3",
		"repository": map[string]any{"url": "git+https://github.com/research-engineering/agentic-proofkit.git"},
	})
	writeNPMArtifact(t, root, testNPMTarballName, []byte("package"))
	writeJSON(t, filepath.Join(root, "artifacts", "pypi", "python-packages.json"), map[string]any{
		"packageName":    testPythonPackageName,
		"packageVersion": "1.2.3",
		"packages": []any{
			map[string]any{"name": testPythonPackageName, "version": "1.2.3", "filename": testPythonWheelName},
		},
	})
	writeFile(t, filepath.Join(root, "artifacts", "pypi", testPythonWheelName), "wheel")
	writeFile(t, filepath.Join(root, "artifacts", "release", "release-notes.md"), "# notes\n\nRollback: pin consumers with `npm install -D @research-engineering/agentic-proofkit@<previous-version>`.\n")
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
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/coverage-metrics.json"), coverageMetricsFixture())
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-proof-receipt-admission-report.json"), selfEvidenceReportFixture("proofkit.proof-receipt-admission", "proofkit.self-hosting.proof-receipts", "proofkit.proof-receipt-admission.boundary", "proofkit.proof-receipt-admission.receipts"))
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-proof-receipts.json"), map[string]any{
		"receiptSetId":  "proofkit.self-hosting.proof-receipts",
		"schemaVersion": 1,
		"receipts":      []any{proofReceiptFixture()},
		"nonClaims":     []any{"Self-hosting receipts are local advisory evidence."},
	})
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-receipt-producer-admission-report.json"), selfEvidenceReportFixture("proofkit.receipt-producer-admission", "proofkit.receipt-producer-policy", "proofkit.receipt-producer-admission.boundary", "proofkit.receipt-producer-admission.coverage", "proofkit.receipt-producer-admission.receipts"))
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-receipt-producer-admission.json"), map[string]any{
		"policyId":           "proofkit.receipt-producer-policy",
		"schemaVersion":      1,
		"environmentClasses": []any{packageGateEnvironmentClass},
		"producers":          []any{receiptProducerFixture()},
		"receiptKinds":       []any{"proofkit.package-gate"},
		"receipts":           []any{receiptProducerReceiptFixture()},
		"nonClaims":          []any{"Local receipts are advisory evidence."},
	})
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle-admission-report.json"), selfEvidenceReportFixture("proofkit.spec-proof-bundle-admission", "proofkit.self-hosting.spec-proof-bundle", "proofkit.spec-proof-bundle-admission.accepted"))
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json"), specProofBundleFixture())
	return root
}

func writeGitHubActionsSelfEvidence(t *testing.T, root string) {
	t.Helper()
	receipt := proofReceiptFixture()
	receipt["receiptId"] = "receipt.github.actions.package-gate"
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
	producerReceipt["receiptId"] = "receipt.github.actions.package-gate"
	producerReceipt["producerId"] = "github.actions.package"
	producerReceipt["nonClaim"] = "GitHub Actions advisory receipts do not satisfy merge obligations."
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-receipt-producer-admission.json"), map[string]any{
		"environmentClasses": []any{packageGateEnvironmentClass},
		"nonClaims":          []any{"GitHub Actions receipts remain advisory."},
		"policyId":           "proofkit.receipt-producer-policy",
		"producers":          []any{producer},
		"receiptKinds":       []any{"proofkit.package-gate"},
		"receipts":           []any{producerReceipt},
		"schemaVersion":      1,
	})

	bundle := specProofBundleFixture()
	receiptAdmission := bundle["receiptAdmission"].(map[string]any)
	receiptAdmission["receipts"] = []any{receipt}
	producerAdmission := bundle["receiptProducerAdmission"].(map[string]any)
	producerAdmission["producers"] = []any{producer}
	producerAdmission["receipts"] = []any{producerReceipt}
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json"), bundle)
}

func writeMixedSelfEvidenceIdentity(t *testing.T, root string) {
	t.Helper()
	githubProducer := receiptProducerFixture()
	githubProducer["producerId"] = "github.actions.package"
	githubProducer["nonClaim"] = "GitHub Actions package receipts are advisory."
	githubProducerReceipt := receiptProducerReceiptFixture()
	githubProducerReceipt["receiptId"] = "receipt.github.actions.package-gate"
	githubProducerReceipt["producerId"] = "github.actions.package"
	githubProducerReceipt["nonClaim"] = "GitHub Actions advisory receipts do not satisfy merge obligations."
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-receipt-producer-admission.json"), map[string]any{
		"environmentClasses": []any{packageGateEnvironmentClass},
		"nonClaims":          []any{"Mixed fixture must be rejected."},
		"policyId":           "proofkit.receipt-producer-policy",
		"producers":          []any{githubProducer},
		"receiptKinds":       []any{"proofkit.package-gate"},
		"receipts":           []any{githubProducerReceipt},
		"schemaVersion":      1,
	})
	bundle := specProofBundleFixture()
	producerAdmission := bundle["receiptProducerAdmission"].(map[string]any)
	producerAdmission["producers"] = []any{githubProducer}
	producerAdmission["receipts"] = []any{githubProducerReceipt}
	writeJSON(t, filepath.Join(root, "artifacts/proofkit/self-hosting-spec-proof-bundle.json"), bundle)
}

func coverageMetricsFixture() map[string]any {
	return map[string]any{
		"artifactKind":  "proofkit.coverage-metrics.v1",
		"schemaVersion": 1,
		"requirements":  map[string]any{"blocking": 1},
		"proofBindings": map[string]any{"boundRequirementCount": 1},
		"witnessPlan":   map[string]any{"commandCount": 1},
		"cliContract":   map[string]any{"commandCount": 1},
		"commandRoutes": map[string]any{
			"admittedInventoryEntryCount":               1,
			"commandCount":                              1,
			"commandWithoutSemanticFalsifierRouteCount": 0,
			"commandsWithoutSemanticFalsifierRoute":     []any{},
			"contractOnlyCommandCount":                  0,
			"contractOnlyCommands":                      []any{},
			"routeCount":                                1,
			"routeOnlyCommandCount":                     0,
			"routeOnlyCommands":                         []any{},
			"routeSmokeCount":                           0,
			"semanticInventoryEntryCount":               1,
			"semanticRouteCount":                        1,
			"unknownSemanticCommandRefCount":            0,
			"unknownSemanticCommandRefs":                []any{},
		},
		"deadZones": map[string]any{
			"bindingWithoutRequirementIds":  []any{},
			"requirementWithoutBindingIds":  []any{},
			"scenarioWithoutCommandIds":     []any{},
			"scenarioWithoutRequirementIds": []any{},
		},
		"nonClaims": []any{"Coverage metrics do not prove runtime readiness."},
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

func proofReceiptFixture() map[string]any {
	return map[string]any{
		"artifactRefs":           []any{map[string]any{"kind": "artifact", "path": "artifacts/package/" + testNPMTarballName, "sha256": "sha256:abc"}},
		"environmentClass":       packageGateEnvironmentClass,
		"evidenceRefs":           []any{"artifacts/package/npm-pack.json"},
		"exitCode":               0,
		"nonClaims":              []any{"Self-hosting proof receipts do not approve merge."},
		"producerAdmissionClass": "advisory",
		"producerId":             "local.developer",
		"proofPlanId":            "proofkit.self-hosting.witness-plan",
		"provenanceRef":          "artifacts/proofkit/ci-provenance.json",
		"receiptId":              "receipt.local.package-gate",
		"receiptKind":            "proofkit.package-gate",
		"runnerClass":            "local",
		"status":                 "passed",
		"witnessSelectors":       []any{"REQ-PROOFKIT-PACKAGE-004"},
	}
}

func receiptProducerFixture() map[string]any {
	return map[string]any{
		"admissionLevel":     "advisory",
		"environmentClasses": []any{packageGateEnvironmentClass},
		"evidenceRefs":       []any{"AGENTS.md"},
		"nonClaim":           "Local developer receipts are advisory.",
		"owner":              "proofkit.package-boundary",
		"producerId":         "local.developer",
		"receiptKinds":       []any{"proofkit.package-gate"},
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
		"receiptId":                "receipt.local.package-gate",
		"receiptKind":              "proofkit.package-gate",
		"satisfiesMergeObligation": false,
		"status":                   "passed",
		"subjectRef":               "proofkit.package-boundary.self-hosting",
	}
}

func specProofBundleFixture() map[string]any {
	return map[string]any{
		"bundleId":                "proofkit.self-hosting.spec-proof-bundle",
		"mergeRequiredReceiptIds": []any{},
		"nonClaims":               []any{"Self-hosting bundle is local advisory evidence."},
		"receiptAdmission": map[string]any{
			"exitCode":  0,
			"failures":  []any{},
			"nonClaims": []any{"Proof receipt admission remains local advisory evidence."},
			"receipts":  []any{proofReceiptFixture()},
			"report":    selfEvidenceReportFixture("proofkit.proof-receipt-admission", "proofkit.self-hosting.proof-receipts", "proofkit.proof-receipt-admission.boundary", "proofkit.proof-receipt-admission.receipts"),
		},
		"receiptProducerAdmission": map[string]any{
			"environmentClasses": []any{packageGateEnvironmentClass},
			"exitCode":           0,
			"failures":           []any{},
			"nonClaims":          []any{"Receipt producer admission remains local advisory evidence."},
			"producers":          []any{receiptProducerFixture()},
			"receiptKinds":       []any{"proofkit.package-gate"},
			"receipts":           []any{receiptProducerReceiptFixture()},
			"report":             selfEvidenceReportFixture("proofkit.receipt-producer-admission", "proofkit.receipt-producer-policy", "proofkit.receipt-producer-admission.boundary", "proofkit.receipt-producer-admission.coverage", "proofkit.receipt-producer-admission.receipts"),
		},
		"requirementBindings": map[string]any{
			"bindingId": "proofkit.package-boundary.requirement-bindings",
			"bindings": []any{map[string]any{
				"commandIds":         []any{"proofkit.ci-receipt-anchor", "proofkit.package-gate"},
				"environmentClasses": []any{packageGateEnvironmentClass},
				"requirementId":      "REQ-PROOFKIT-PACKAGE-004",
				"scenarioId":         "proofkit.package-boundary.ci-receipt-anchor",
				"witnessId":          "proofkit.ci.receipt-anchor",
				"witnessKind":        "contract",
				"witnessPath":        "scripts/validate-self-hosting-receipts.go",
			}},
			"nonClaims": []any{"Requirement bindings do not execute witnesses."},
			"requirements": []any{map[string]any{
				"ownerId":       "proofkit.package-boundary",
				"proofState":    "witness_backed",
				"requirementId": "REQ-PROOFKIT-PACKAGE-004",
				"specPath":      "docs/specs/proofkit-package-boundary/requirements.v1.json",
			}},
			"schemaVersion":   1,
			"witnessCommands": []any{map[string]any{"command": "npm run self:receipt", "commandId": "proofkit.ci-receipt-anchor", "environmentClass": packageGateEnvironmentClass}},
		},
		"schemaVersion": 1,
		"witnessPlan": map[string]any{
			"commands": []any{map[string]any{
				"expectedArtifacts": []any{map[string]any{"kind": "report", "path": "artifacts/proofkit/self-hosting-spec-proof-bundle.json", "required": true}},
				"id":                "proofkit.ci-receipt-anchor",
			}},
			"nonClaims": []any{"Witness plan does not execute commands."},
			"policies": []any{map[string]any{
				"commandId":          "proofkit.ci-receipt-anchor",
				"environmentClasses": []any{packageGateEnvironmentClass},
				"sideEffectClass":    "write-local",
			}},
			"schedulerPlanId": "proofkit.self-hosting.witness-plan",
			"schemaVersion":   1,
			"vocabulary":      map[string]any{"environmentClasses": []any{packageGateEnvironmentClass}},
		},
	}
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
		pypi["nonClaims"] = []any{"PyPI is not registry authority for this candidate."}
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

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(content))
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
