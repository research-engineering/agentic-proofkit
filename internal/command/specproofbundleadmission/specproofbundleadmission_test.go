package specproofbundleadmission

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/proofreceiptadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestOptionalChildRejectsInconsistentChildResult(t *testing.T) {
	cases := []struct {
		name     string
		state    string
		exitCode string
		failures []any
		want     string
	}{
		{
			name:     "passed with non-zero exit code",
			state:    "passed",
			exitCode: "1",
			failures: []any{},
			want:     "passed with non-zero exitCode",
		},
		{
			name:     "passed with failures",
			state:    "passed",
			exitCode: "0",
			failures: []any{"failure"},
			want:     "passed with failures",
		},
		{
			name:     "failed with zero exit code",
			state:    "failed",
			exitCode: "0",
			failures: []any{"failure"},
			want:     "failed with zero exitCode",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, err := optionalChild(childReportValue(item.state, item.exitCode, item.failures), "receipt admission", "proofkit.proof-receipt-admission")
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("optionalChild() error = %v, want %q", err, item.want)
			}
		})
	}
}

func TestOptionalChildAcceptsConsistentPassedChildResult(t *testing.T) {
	child, err := optionalChild(childReportValue("passed", "0", []any{}), "receipt admission", "proofkit.proof-receipt-admission")
	if err != nil {
		t.Fatalf("optionalChild() error = %v", err)
	}
	if child.State != "passed" || child.ExitCode != 0 || len(child.Failures) != 0 || len(child.Receipts) != 1 {
		t.Fatalf("optionalChild() child = %#v", child)
	}
}

func TestBuildAcceptsCurrentBundleLinkage(t *testing.T) {
	record, exitCode, err := Build(validBundleInput(t))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if exitCode != 0 || record.State != "passed" {
		encoded, err := json.MarshalIndent(record.JSONValue(), "", "  ")
		if err != nil {
			t.Fatalf("marshal failed bundle report: %v", err)
		}
		t.Fatalf("Build() exitCode=%d state=%s report=%s", exitCode, record.State, string(encoded))
	}
}

func TestBundleLinkageUsesReceiptProducerProjection(t *testing.T) {
	sourcePath := filepath.Join(repoRoot(t), "internal", "command", "specproofbundleadmission", "specproofbundleadmission.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read bundle admission source: %v", err)
	}
	for _, forbidden := range []string{
		"for _, receipt := range receiptProducer.Receipts",
		"producerReceipts := map[string]map[string]any{}",
	} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("bundle linkage rereads raw receipt producer child maps: %q", forbidden)
		}
	}
}

func TestBuildRejectsInconsistentReceiptAdmissionChild(t *testing.T) {
	input := validBundleInput(t)
	receiptAdmission := input["receiptAdmission"].(map[string]any)
	receiptAdmission["exitCode"] = json.Number("1")

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "passed with non-zero exitCode") {
		t.Fatalf("Build() error = %v, want inconsistent child rejection", err)
	}
}

func TestBuildRejectsUnknownReceiptSelector(t *testing.T) {
	input := validBundleInput(t)
	receiptAdmission := input["receiptAdmission"].(map[string]any)
	receipt := validProofReceipt()
	receipt["witnessSelectors"] = []any{"REQ-PROOFKIT-UNKNOWN"}
	receiptAdmission["receipts"] = []any{
		receipt,
	}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exitCode=%d state=%s, want failed report", exitCode, record.State)
	}
	assertFailedRuleMessage(t, record.RuleResults, "proofkit.spec-proof-bundle-admission.failure.", "witness selector is not a requirement or scenario id")
}

func TestBuildRejectsReceiptKindThatDoesNotCoverWitnessSelector(t *testing.T) {
	input := validBundleInput(t)
	receipt := validProofReceipt()
	receipt["receiptKind"] = "proofkit.go-test"
	receipt["witnessSelectors"] = []any{"REQ-PROOFKIT-PACKAGE-004"}
	input["receiptAdmission"] = proofReceiptChild(t, []any{receipt})

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exitCode=%d state=%s, want failed report", exitCode, record.State)
	}
	assertFailedRuleMessage(t, record.RuleResults, "proofkit.spec-proof-bundle-admission.failure.", "does not cover witness selector")
}

func TestBuildRejectsBindingThatOmitsWitnessCommandEnvironment(t *testing.T) {
	input := validBundleInput(t)
	requirementBindings := input["requirementBindings"].(map[string]any)
	bindings := requirementBindings["bindings"].([]any)
	for _, raw := range bindings {
		binding := raw.(map[string]any)
		if binding["scenarioId"] != "proofkit.supply-chain-quality.proof-class-ci-split" {
			continue
		}
		binding["environmentClasses"] = []any{"local-go"}
		break
	}

	record, exitCode, err := Build(input)
	if err != nil {
		t.Fatalf("Build() unexpected error = %v", err)
	}
	if exitCode == 0 || record.State != "failed" {
		t.Fatalf("Build() exitCode=%d state=%s, want failed report", exitCode, record.State)
	}
	assertFailedRuleMessage(t, record.RuleResults, "proofkit.spec-proof-bundle-admission.failure.", "binding scenario proofkit.supply-chain-quality.proof-class-ci-split omits witness-plan command proofkit.platform-smoke environment local-python")
}

func childReportValue(state string, exitCode string, failures []any) map[string]any {
	child := mustProofReceiptChild([]any{validProofReceipt()})
	child["exitCode"] = json.Number(exitCode)
	child["failures"] = failures
	report := child["report"].(map[string]any)
	report["state"] = state
	return child
}

func childReportValueWithReceipts(state string, exitCode string, failures []any, receipts []any) map[string]any {
	child := mustProofReceiptChild(receipts)
	child["exitCode"] = json.Number(exitCode)
	child["failures"] = failures
	report := child["report"].(map[string]any)
	report["state"] = state
	return child
}

func TestBuildRejectsForgedReceiptAdmissionChild(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.032888675717298205828739761733737136832901453189109010451175224295171303909603")
	input := validBundleInput(t)
	receiptAdmission := input["receiptAdmission"].(map[string]any)
	receiptAdmission["receipts"] = []any{
		map[string]any{
			"producerAdmissionClass": "advisory",
			"proofPlanId":            "proofkit.self-hosting.witness-plan",
			"receiptId":              "receipt.test.forged",
			"receiptKind":            "proofkit.go-test",
			"status":                 "passed",
			"witnessSelectors":       []any{"REQ-PROOFKIT-PACKAGE-001"},
		},
	}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "not admitted by owner validator") {
		t.Fatalf("Build() error = %v, want owner validator rejection", err)
	}
}

func TestBuildRejectsForgedReceiptAdmissionReportBody(t *testing.T) {
	input := validBundleInput(t)
	receiptAdmission := input["receiptAdmission"].(map[string]any)
	report := receiptAdmission["report"].(map[string]any)
	summary := report["summary"].(map[string]any)
	summary["receiptCount"] = json.Number("999")

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "report body does not match owner validator result") {
		t.Fatalf("Build() error = %v, want owner body mismatch", err)
	}
}

func TestBuildRejectsMergeObligationLinkageFailures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "missing merge required receipt",
			mutate: func(input map[string]any) {
				input["mergeRequiredReceiptIds"] = []any{"receipt.test.missing"}
			},
			want: "merge-required receipt is missing",
		},
		{
			name: "non passed merge receipt",
			mutate: func(input map[string]any) {
				receipt := mergeProofReceipt()
				receipt["status"] = "failed"
				input["receiptAdmission"] = proofReceiptChild(t, []any{receipt})
			},
			want: "merge-required receipt must pass",
		},
		{
			name: "advisory merge required receipt",
			mutate: func(input map[string]any) {
				receipt := mergeProofReceipt()
				receipt["producerAdmissionClass"] = "advisory"
				receipt["producerId"] = "local.test"
				input["receiptAdmission"] = proofReceiptChild(t, []any{receipt})
				input["receiptProducerAdmission"] = nil
			},
			want: "merge-required receipt must use merge_satisfying producer admission",
		},
		{
			name: "missing producer child",
			mutate: func(input map[string]any) {
				input["receiptProducerAdmission"] = nil
			},
			want: "merge_satisfying receipts require an attached receiptProducerAdmission report",
		},
		{
			name: "missing producer row",
			mutate: func(input map[string]any) {
				input["receiptProducerAdmission"] = producerAdmissionChild(t, []any{}, []any{}, []any{"proofkit.go-test"}, []any{"local-go"})
			},
			want: "merge_satisfying receipt lacks producer admission row",
		},
		{
			name: "producer field drift",
			mutate: func(input map[string]any) {
				producerChild := input["receiptProducerAdmission"].(map[string]any)
				receipt := producerChild["receipts"].([]any)[0].(map[string]any)
				receipt["status"] = "failed"
				input["receiptProducerAdmission"] = producerAdmissionChild(t, producerChild["producers"].([]any), producerChild["receipts"].([]any), []any{"proofkit.go-test"}, []any{"local-go"})
			},
			want: "status does not match producer admission row",
		},
		{
			name: "producer row does not satisfy merge obligation",
			mutate: func(input map[string]any) {
				producerChild := input["receiptProducerAdmission"].(map[string]any)
				receipt := producerChild["receipts"].([]any)[0].(map[string]any)
				receipt["satisfiesMergeObligation"] = false
				input["receiptProducerAdmission"] = producerAdmissionChild(t, producerChild["producers"].([]any), producerChild["receipts"].([]any), []any{"proofkit.go-test"}, []any{"local-go"})
			},
			want: "producer admission row is not merge-obligation satisfying",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validMergeBundleInput(t)
			item.mutate(input)

			record, exitCode, err := Build(input)
			if err != nil {
				t.Fatalf("Build() unexpected error = %v", err)
			}
			if exitCode == 0 || record.State != "failed" {
				t.Fatalf("Build() exitCode=%d state=%s, want failed report", exitCode, record.State)
			}
			assertFailedRuleMessage(t, record.RuleResults, "proofkit.spec-proof-bundle-admission.failure.", item.want)
		})
	}
}

func assertFailedRuleMessage(t *testing.T, rules []report.RuleResult, rulePrefix string, want string) {
	t.Helper()
	for _, rule := range rules {
		if !strings.HasPrefix(rule.RuleID, rulePrefix) {
			continue
		}
		if rule.Status != "failed" {
			t.Fatalf("%s status=%s, want failed", rule.RuleID, rule.Status)
		}
		if strings.Contains(rule.Message, want) {
			return
		}
	}
	t.Fatalf("failed rule with prefix %q does not contain %q: %#v", rulePrefix, want, rules)
}

func TestBuildRejectsProducerChildVocabularyNarrowing(t *testing.T) {
	input := validMergeBundleInput(t)
	producerChild := input["receiptProducerAdmission"].(map[string]any)
	producerChild["receiptKinds"] = []any{}

	_, _, err := Build(input)
	if err == nil || !strings.Contains(err.Error(), "not admitted by owner validator") {
		t.Fatalf("Build() error = %v, want producer vocabulary rejection", err)
	}
}

func validBundleInput(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"bundleId":                 "proofkit.test.spec-proof-bundle",
		"mergeRequiredReceiptIds":  []any{},
		"nonClaims":                []any{"Test bundle input does not claim release, rollout, or production readiness."},
		"receiptAdmission":         childReportValueWithReceipts("passed", "0", []any{}, []any{validProofReceipt()}),
		"receiptProducerAdmission": nil,
		"requirementBindings":      readRepoJSON(t, "proofkit/requirement-bindings.json"),
		"schemaVersion":            json.Number("1"),
		"witnessPlan":              readRepoJSON(t, "proofkit/witness-plan.json"),
	}
}

func validMergeBundleInput(t *testing.T) map[string]any {
	t.Helper()
	receipt := mergeProofReceipt()
	return map[string]any{
		"bundleId":                 "proofkit.test.spec-proof-bundle",
		"mergeRequiredReceiptIds":  []any{"receipt.test.one"},
		"nonClaims":                []any{"Test bundle input does not claim release, rollout, or production readiness."},
		"receiptAdmission":         proofReceiptChild(t, []any{receipt}),
		"receiptProducerAdmission": producerAdmissionChild(t, []any{validProducer()}, []any{validProducerReceipt()}, []any{"proofkit.go-test"}, []any{"local-go"}),
		"requirementBindings":      readRepoJSON(t, "proofkit/requirement-bindings.json"),
		"schemaVersion":            json.Number("1"),
		"witnessPlan":              readRepoJSON(t, "proofkit/witness-plan.json"),
	}
}

func validProofReceipt() map[string]any {
	return map[string]any{
		"artifactRefs": []any{
			map[string]any{"kind": "report", "path": "artifacts/test/report.json", "sha256": digestText()},
		},
		"commandDigest":          digestText(),
		"dependencyDigest":       nil,
		"environmentClass":       "local-go",
		"environmentDigest":      digestText(),
		"evidenceRefs":           []any{"artifacts/test/report.json"},
		"exitCode":               json.Number("0"),
		"finishedAt":             "2026-06-22T00:00:01Z",
		"lockfileDigest":         nil,
		"nonClaims":              []any{"Test receipt does not claim freshness."},
		"preconditionDigest":     digestText(),
		"producerAdmissionClass": "advisory",
		"producerId":             "local.test",
		"proofBindingDigest":     digestText(),
		"proofPlanId":            "proofkit.self-hosting.witness-plan",
		"provenanceRef":          "artifacts/test/provenance.json",
		"receiptId":              "receipt.test.one",
		"receiptKind":            "proofkit.go-test",
		"runnerClass":            "local",
		"runnerIdentity":         "local.test",
		"sourceRevision":         "test-revision",
		"startedAt":              "2026-06-22T00:00:00Z",
		"status":                 "passed",
		"toolchainDigest":        digestText(),
		"witnessSelectorDigest":  digestText(),
		"witnessSelectors":       []any{"REQ-PROOFKIT-PACKAGE-001"},
	}
}

func mergeProofReceipt() map[string]any {
	receipt := validProofReceipt()
	receipt["producerAdmissionClass"] = "merge_satisfying"
	receipt["producerId"] = "github.actions.package.protected"
	return receipt
}

func validProducer() map[string]any {
	return map[string]any{
		"admissionLevel":     "merge_satisfying",
		"environmentClasses": []any{"local-go"},
		"evidenceRefs":       []any{"proofkit/receipt-producer-policy.json"},
		"nonClaim":           "Test protected producer does not prove live workflow identity.",
		"owner":              "proofkit.test",
		"producerId":         "github.actions.package.protected",
		"receiptKinds":       []any{"proofkit.go-test"},
	}
}

func validProducerReceipt() map[string]any {
	return map[string]any{
		"artifactRefs":             []any{"artifacts/test/report.json"},
		"environmentClass":         "local-go",
		"evidenceRef":              "artifacts/test/report.json",
		"nonClaim":                 "Test producer receipt does not prove live workflow identity.",
		"producerId":               "github.actions.package.protected",
		"provenanceRef":            "artifacts/test/provenance.json",
		"receiptId":                "receipt.test.one",
		"receiptKind":              "proofkit.go-test",
		"satisfiesMergeObligation": true,
		"status":                   "passed",
		"subjectRef":               "proofkit.package-boundary.self-hosting",
	}
}

func proofReceiptChild(t *testing.T, receipts []any) map[string]any {
	t.Helper()
	child, err := buildProofReceiptChild(receipts)
	if err != nil {
		t.Fatalf("proof receipt admission: %v", err)
	}
	return child
}

func mustProofReceiptChild(receipts []any) map[string]any {
	child, err := buildProofReceiptChild(receipts)
	if err != nil {
		panic(err)
	}
	return child
}

func buildProofReceiptChild(receipts []any) (map[string]any, error) {
	nonClaims := []any{"Test child report does not claim producer authenticity."}
	record, exitCode, err := proofreceiptadmission.Build(map[string]any{
		"schemaVersion": json.Number("1"),
		"receiptSetId":  "proofkit.test.child-report",
		"receipts":      receipts,
		"nonClaims":     nonClaims,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"exitCode":  json.Number(fmt.Sprint(exitCode)),
		"failures":  []any{},
		"nonClaims": nonClaims,
		"producers": []any{},
		"receipts":  receipts,
		"report":    record.JSONValue(),
	}, nil
}

func producerAdmissionChild(t *testing.T, producers []any, receipts []any, receiptKinds []any, environmentClasses []any) map[string]any {
	t.Helper()
	nonClaims := []any{"Test producer admission input does not authenticate producers."}
	record, exitCode, err := receiptproduceradmission.Build(map[string]any{
		"schemaVersion":      json.Number("1"),
		"policyId":           "proofkit.test.producer-policy",
		"receiptKinds":       receiptKinds,
		"environmentClasses": environmentClasses,
		"producers":          producers,
		"receipts":           receipts,
		"nonClaims":          nonClaims,
	})
	if err != nil {
		t.Fatalf("receipt producer admission: %v", err)
	}
	return map[string]any{
		"environmentClasses": environmentClasses,
		"exitCode":           json.Number(fmt.Sprint(exitCode)),
		"failures":           []any{},
		"nonClaims":          nonClaims,
		"producers":          producers,
		"receiptKinds":       receiptKinds,
		"receipts":           receipts,
		"report":             record.JSONValue(),
	}
}

func digestText() string {
	return "sha256:" + strings.Repeat("a", 64)
}

func readRepoJSON(t *testing.T, path string) any {
	t.Helper()
	file, err := os.Open(filepath.Join(repoRoot(t), path))
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	value, err := admission.DecodeJSON(file, 8<<20)
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return value
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}
