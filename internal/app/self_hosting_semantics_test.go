package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestSelfHostingProofCoreCommandsAcceptCurrentRecords(t *testing.T) {
	cases := []struct {
		command string
		path    string
	}{
		{command: "requirement-bindings", path: "proofkit/requirement-bindings.json"},
		{command: "witness-scheduler-plan", path: "proofkit/witness-plan.json"},
	}
	for _, path := range requirementSourcePaths(t) {
		cases = append(cases, struct {
			command string
			path    string
		}{command: "requirement-source-admission", path: path})
	}
	for _, item := range cases {
		t.Run(item.command+"/"+item.path, func(t *testing.T) {
			output := runCommandWithFile(t, item.command, filepath.Join(repoRoot(t), item.path))
			assertReportState(t, output, "passed")
		})
	}
}

func requirementSourcePaths(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	matches, err := filepath.Glob(filepath.Join(root, "docs", "specs", "*", "requirements.v1.json"))
	if err != nil {
		t.Fatalf("glob requirement sources: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no requirement sources found")
	}
	paths := make([]string, 0, len(matches))
	for _, match := range matches {
		relative, err := filepath.Rel(root, match)
		if err != nil {
			t.Fatalf("rel requirement source: %v", err)
		}
		paths = append(paths, filepath.ToSlash(relative))
	}
	sort.Strings(paths)
	return paths
}

func TestSelfHostingWitnessBackedBindingsReferenceExistingSurfaces(t *testing.T) {
	bindings := readJSONFile(t, "proofkit/requirement-bindings.json").(map[string]any)
	witnessBackedRequirementIDs := map[string]struct{}{}
	for _, item := range bindings["requirements"].([]any) {
		requirement := item.(map[string]any)
		if requirement["proofState"] == "witness_backed" {
			witnessBackedRequirementIDs[requirement["requirementId"].(string)] = struct{}{}
		}
	}
	if len(witnessBackedRequirementIDs) == 0 {
		t.Fatal("self-hosting bindings have no witness-backed requirements to verify")
	}
	root := repoRoot(t)
	checked := 0
	for _, item := range bindings["bindings"].([]any) {
		binding := item.(map[string]any)
		requirementID := binding["requirementId"].(string)
		if _, ok := witnessBackedRequirementIDs[requirementID]; !ok {
			continue
		}
		checked++
		witnessPath, ok := binding["witnessPath"].(string)
		if !ok || witnessPath == "" {
			t.Fatalf("%s/%s witness_backed binding has no witnessPath", binding["requirementId"], binding["scenarioId"])
		}
		if strings.HasPrefix(witnessPath, "proofkit.virtual/") {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, witnessPath)); err != nil {
			t.Fatalf("%s/%s witnessPath %q does not exist: %v", binding["requirementId"], binding["scenarioId"], witnessPath, err)
		}
	}
	if checked == 0 {
		t.Fatal("self-hosting witness-backed requirements have no bindings to verify")
	}
}

func TestSelfHostingRequirementBindingRecordsPreserveSourceAuthority(t *testing.T) {
	type sourceRequirement struct {
		claimLevel string
		nonClaims  map[string]struct{}
		ownerID    string
		specPath   string
	}
	sources := map[string]sourceRequirement{}
	for _, path := range requirementSourcePaths(t) {
		record := readJSONFile(t, path).(map[string]any)
		for _, value := range record["requirements"].([]any) {
			requirement := value.(map[string]any)
			requirementID := requirement["requirementId"].(string)
			if _, exists := sources[requirementID]; exists {
				t.Fatalf("duplicate source requirementId %s", requirementID)
			}
			nonClaims := map[string]struct{}{}
			for _, nonClaim := range requirement["nonClaims"].([]any) {
				nonClaims[nonClaim.(string)] = struct{}{}
			}
			sources[requirementID] = sourceRequirement{
				claimLevel: requirement["claimLevel"].(string),
				nonClaims:  nonClaims,
				ownerID:    requirement["ownerId"].(string),
				specPath:   path,
			}
		}
	}

	bindings := readJSONFile(t, "proofkit/requirement-bindings.json").(map[string]any)
	bound := map[string]struct{}{}
	for _, value := range bindings["requirements"].([]any) {
		requirement := value.(map[string]any)
		requirementID := requirement["requirementId"].(string)
		source, ok := sources[requirementID]
		if !ok {
			t.Fatalf("binding requirement %s has no source owner record", requirementID)
		}
		bound[requirementID] = struct{}{}
		if requirement["ownerId"] != source.ownerID || requirement["claimLevel"] != source.claimLevel || requirement["specPath"] != source.specPath {
			t.Fatalf("binding requirement %s changed source identity: binding=%#v source=%#v", requirementID, requirement, source)
		}
		bindingNonClaims := map[string]struct{}{}
		for _, nonClaim := range requirement["nonClaims"].([]any) {
			bindingNonClaims[nonClaim.(string)] = struct{}{}
		}
		for nonClaim := range source.nonClaims {
			if _, ok := bindingNonClaims[nonClaim]; !ok {
				t.Fatalf("binding requirement %s dropped source nonClaim %q", requirementID, nonClaim)
			}
		}
	}
	for requirementID := range sources {
		if _, ok := bound[requirementID]; !ok {
			t.Fatalf("source requirement %s has no binding requirement record", requirementID)
		}
	}
}

func TestSelfHostingProofCoreCommandsRejectBrokenLinkage(t *testing.T) {
	bindings := readJSONFile(t, "proofkit/requirement-bindings.json")
	bindingRecord := bindings.(map[string]any)
	bindingItems := bindingRecord["bindings"].([]any)
	firstBinding := bindingItems[0].(map[string]any)
	firstBinding["commandIds"] = []any{"proofkit.unknown-command"}
	output := runCommandWithValue(t, "requirement-bindings", bindings)
	assertReportState(t, output, "failed")
	assertOutputContains(t, output, "unknown commandId=proofkit.unknown-command")

	witnessPlan := readJSONFile(t, "proofkit/witness-plan.json")
	witnessRecord := witnessPlan.(map[string]any)
	policies := witnessRecord["policies"].([]any)
	for _, item := range policies {
		policy := item.(map[string]any)
		if policy["commandId"] == "proofkit.go-test" || policy["commandId"] == "proofkit.package-artifact" {
			policy["resourceWrites"] = []any{"resource.proofkit.local-artifacts"}
			policy["sideEffectClass"] = "local_write"
		}
	}
	commands := witnessRecord["commands"].([]any)
	for _, item := range commands {
		command := item.(map[string]any)
		if command["id"] == "proofkit.go-test" {
			command["parallelGroup"] = "package-artifact"
		}
	}
	output = runCommandWithValue(t, "witness-scheduler-plan", witnessPlan)
	assertReportState(t, output, "failed")
	assertOutputContains(t, output, "write/write resource collision")
}

func TestReceiptAuthorityCommandsAcceptAndRejectProofShape(t *testing.T) {
	receiptInput := validProofReceiptInput()
	output := runCommandWithValue(t, "proof-receipt-admission", receiptInput)
	assertReportState(t, output, "passed")

	brokenReceiptInput := validProofReceiptInput()
	receipts := brokenReceiptInput["receipts"].([]any)
	receipts = append(receipts, receipts[0])
	brokenReceiptInput["receipts"] = receipts
	status, _, stderr := runCommandWithValueAllowingAdmissionError(t, "proof-receipt-admission", brokenReceiptInput)
	if status != 1 || !strings.Contains(stderr, "receipt ids") {
		t.Fatalf("expected duplicate receipt admission failure, status=%d stderr=%s", status, stderr)
	}

	producerInput := validReceiptProducerInput(false)
	output = runCommandWithValue(t, "receipt-producer-admission", producerInput)
	assertReportState(t, output, "passed")

	brokenProducerInput := validReceiptProducerInput(true)
	output = runCommandWithValue(t, "receipt-producer-admission", brokenProducerInput)
	assertReportState(t, output, "failed")
	assertOutputContains(t, output, "merge")
}

func TestProofReceiptAdmissionRejectsRiskCorpus(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "bad digest",
			mutate: func(input map[string]any) {
				receipt(input)["proofBindingDigest"] = "sha256:not-hex"
			},
			want: "sha256",
		},
		{
			name: "unsupported receipt field",
			mutate: func(input map[string]any) {
				receipt(input)["unexpected"] = true
			},
			want: "unsupported field",
		},
		{
			name: "invalid timestamp",
			mutate: func(input map[string]any) {
				receipt(input)["startedAt"] = "2026-06-22 00:00:00"
			},
			want: "RFC3339 UTC timestamp",
		},
		{
			name: "duplicate artifact ref",
			mutate: func(input map[string]any) {
				artifact := receipt(input)["artifactRefs"].([]any)[0]
				receipt(input)["artifactRefs"] = []any{artifact, artifact}
			},
			want: "artifact refs",
		},
		{
			name: "passed without artifact refs",
			mutate: func(input map[string]any) {
				receipt(input)["artifactRefs"] = []any{}
			},
			want: "without artifact refs",
		},
		{
			name: "blocked without proof scope non-claims",
			mutate: func(input map[string]any) {
				receipt(input)["status"] = "blocked"
				receipt(input)["exitCode"] = nil
				receipt(input)["nonClaims"] = []any{}
			},
			want: "without proof-scope non-claims",
		},
		{
			name: "path escape",
			mutate: func(input map[string]any) {
				artifact := receipt(input)["artifactRefs"].([]any)[0].(map[string]any)
				artifact["path"] = "../secret.json"
			},
			want: "escape the repository",
		},
		{
			name: "drive-like path",
			mutate: func(input map[string]any) {
				artifact := receipt(input)["artifactRefs"].([]any)[0].(map[string]any)
				artifact["path"] = "C:/outside/report.json"
			},
			want: "repository-relative POSIX path",
		},
		{
			name: "unsorted selectors",
			mutate: func(input map[string]any) {
				receipt(input)["witnessSelectors"] = []any{"REQ-TEST-002", "REQ-TEST-001"}
			},
			want: "sorted and unique",
		},
		{
			name: "finished before started",
			mutate: func(input map[string]any) {
				receipt(input)["finishedAt"] = "2026-06-21T23:59:59Z"
			},
			want: "finished before it started",
		},
		{
			name: "passed without exit code",
			mutate: func(input map[string]any) {
				receipt(input)["exitCode"] = nil
			},
			want: "without exitCode",
		},
		{
			name: "passed with non-zero exit code",
			mutate: func(input map[string]any) {
				receipt(input)["exitCode"] = json.Number("1")
			},
			want: "passed with non-zero exitCode",
		},
		{
			name: "failed with zero exit code",
			mutate: func(input map[string]any) {
				receipt(input)["status"] = "failed"
			},
			want: "failed with zero exitCode",
		},
		{
			name: "blocked with exit code",
			mutate: func(input map[string]any) {
				receipt(input)["status"] = "blocked"
			},
			want: "with exitCode",
		},
		{
			name: "merge satisfying without provenance",
			mutate: func(input map[string]any) {
				receipt(input)["producerAdmissionClass"] = "merge_satisfying"
				receipt(input)["provenanceRef"] = nil
			},
			want: "without provenanceRef",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := cloneMap(t, validProofReceiptInput())
			item.mutate(input)
			status, stdout, stderr := runCommandWithValueAllowingAdmissionError(t, "proof-receipt-admission", input)
			if status == 0 {
				t.Fatalf("expected failure, stdout=%s stderr=%s", stdout, stderr)
			}
			if !strings.Contains(stdout+stderr, item.want) {
				t.Fatalf("expected %q in output, stdout=%s stderr=%s", item.want, stdout, stderr)
			}
		})
	}
}

func TestReceiptProducerAdmissionRejectsRiskCorpus(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "unknown producer",
			mutate: func(input map[string]any) {
				producerReceipt(input)["producerId"] = "local.unknown"
			},
			want: "unknown producer",
		},
		{
			name: "unknown environment class",
			mutate: func(input map[string]any) {
				producerReceipt(input)["environmentClass"] = "local-python"
			},
			want: "declared vocabulary value",
		},
		{
			name: "merge obligation without passed status",
			mutate: func(input map[string]any) {
				producerReceipt(input)["satisfiesMergeObligation"] = true
				producerReceipt(input)["status"] = "failed"
				producer(input)["admissionLevel"] = "merge_satisfying"
			},
			want: "without passed status",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := cloneMap(t, validReceiptProducerInput(false))
			item.mutate(input)
			status, stdout, stderr := runCommandWithValueAllowingAdmissionError(t, "receipt-producer-admission", input)
			if status == 0 {
				t.Fatalf("expected failure, stdout=%s stderr=%s", stdout, stderr)
			}
			if !strings.Contains(stdout+stderr, item.want) {
				t.Fatalf("expected %q in output, stdout=%s stderr=%s", item.want, stdout, stderr)
			}
		})
	}
}

func TestProducerPolicySelfProofRejectsSameChangeTupleProof(t *testing.T) {
	input := validProducerPolicySelfProofInput(true)
	output := runCommandWithValue(t, "producer-policy-self-proof", input)
	assertReportState(t, output, "failed")
	assertOutputContains(t, output, "newly admitted producer tuple")

	brokenLink := validProducerPolicySelfProofInput(false)
	receiptRef := brokenLink["mergeObligationReceiptRefs"].([]any)[0].(map[string]any)
	receiptRef["usedForPolicyChangeId"] = "proofkit.policy.other"
	status, stdout, stderr := runCommandWithValueAllowingAdmissionError(t, "producer-policy-self-proof", brokenLink)
	if status == 0 || !strings.Contains(stdout+stderr, "must match policyChangeId") {
		t.Fatalf("expected policyChangeId linkage failure, status=%d stdout=%s stderr=%s", status, stdout, stderr)
	}
}

func runCommandWithFile(t *testing.T, command string, path string) []byte {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{command, "--input", path}, strings.NewReader(""), &stdout, &stderr)
	if status != 0 {
		t.Fatalf("%s failed status=%d stdout=%s stderr=%s", command, status, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("%s wrote stderr: %s", command, stderr.String())
	}
	return stdout.Bytes()
}

func runCommandWithValue(t *testing.T, command string, value any) []byte {
	t.Helper()
	input, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{command, "--input", "-"}, bytes.NewReader(input), &stdout, &stderr)
	if stderr.Len() != 0 {
		t.Fatalf("%s wrote stderr: %s", command, stderr.String())
	}
	if status != 0 && stdout.Len() == 0 {
		t.Fatalf("%s failed without report", command)
	}
	return stdout.Bytes()
}

func runCommandWithValueAllowingAdmissionError(t *testing.T, command string, value any) (int, string, string) {
	t.Helper()
	input, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{command, "--input", "-"}, bytes.NewReader(input), &stdout, &stderr)
	return status, stdout.String(), stderr.String()
}

func readJSONFile(t *testing.T, path string) any {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot(t), path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var value any
	if err := json.Unmarshal(content, &value); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return value
}

func assertReportState(t *testing.T, output []byte, want string) {
	t.Helper()
	var report map[string]any
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, output)
	}
	if report["state"] != want {
		t.Fatalf("expected state %s, got %v\n%s", want, report["state"], output)
	}
}

func assertOutputContains(t *testing.T, output []byte, needle string) {
	t.Helper()
	if !strings.Contains(string(output), needle) {
		t.Fatalf("output does not contain %q:\n%s", needle, output)
	}
}

func validProofReceiptInput() map[string]any {
	return map[string]any{
		"schemaVersion": 1,
		"receiptSetId":  "proofkit.test.receipts",
		"nonClaims":     []any{"Receipt test input does not claim producer authenticity."},
		"receipts": []any{
			map[string]any{
				"artifactRefs": []any{
					map[string]any{"kind": "report", "path": "artifacts/test/report.json", "sha256": digestText()},
				},
				"commandDigest":          digestText(),
				"dependencyDigest":       nil,
				"environmentClass":       "local-go",
				"environmentDigest":      digestText(),
				"evidenceRefs":           []any{"artifacts/test/report.json"},
				"exitCode":               0,
				"finishedAt":             "2026-06-22T00:00:01Z",
				"lockfileDigest":         nil,
				"nonClaims":              []any{"Receipt test does not claim freshness."},
				"preconditionDigest":     digestText(),
				"producerAdmissionClass": "advisory",
				"producerId":             "local.test",
				"proofBindingDigest":     digestText(),
				"proofPlanId":            "proofkit.test.plan",
				"provenanceRef":          "artifacts/test/provenance.json",
				"receiptId":              "receipt.test.one",
				"receiptKind":            "proofkit.test",
				"runnerClass":            "local",
				"runnerIdentity":         "local.test",
				"sourceRevision":         "test-revision",
				"startedAt":              "2026-06-22T00:00:00Z",
				"status":                 "passed",
				"toolchainDigest":        digestText(),
				"witnessSelectorDigest":  digestText(),
				"witnessSelectors":       []any{"REQ-TEST-001"},
			},
		},
	}
}

func receipt(input map[string]any) map[string]any {
	return input["receipts"].([]any)[0].(map[string]any)
}

func validReceiptProducerInput(forceMergeClaim bool) map[string]any {
	return map[string]any{
		"schemaVersion":      1,
		"policyId":           "proofkit.test.producer-policy",
		"environmentClasses": []any{"local-go"},
		"receiptKinds":       []any{"proofkit.test"},
		"nonClaims":          []any{"Producer test input does not claim producer authenticity."},
		"producers": []any{
			map[string]any{
				"admissionLevel":     "advisory",
				"environmentClasses": []any{"local-go"},
				"evidenceRefs":       []any{"docs/test.md"},
				"nonClaim":           "Test producer is advisory only.",
				"owner":              "proofkit.test",
				"producerId":         "local.test",
				"receiptKinds":       []any{"proofkit.test"},
			},
		},
		"receipts": []any{
			map[string]any{
				"artifactRefs":             []any{"artifacts/test/report.json"},
				"environmentClass":         "local-go",
				"evidenceRef":              "artifacts/test/report.json",
				"nonClaim":                 "Test receipt is synthetic.",
				"producerId":               "local.test",
				"provenanceRef":            "artifacts/test/provenance.json",
				"receiptId":                "receipt.test.one",
				"receiptKind":              "proofkit.test",
				"satisfiesMergeObligation": forceMergeClaim,
				"status":                   "passed",
				"subjectRef":               "proofkit.test.subject",
			},
		},
	}
}

func producer(input map[string]any) map[string]any {
	return input["producers"].([]any)[0].(map[string]any)
}

func producerReceipt(input map[string]any) map[string]any {
	return input["receipts"].([]any)[0].(map[string]any)
}

func validProducerPolicySelfProofInput(newlyAdmittedTuple bool) map[string]any {
	toAdmissionLevel := "advisory"
	changeKind := "add_producer"
	fromAdmissionLevel := any(nil)
	receiptAdmissionClass := "merge_satisfying"
	if newlyAdmittedTuple {
		toAdmissionLevel = "merge_satisfying"
		changeKind = "promote_to_merge_satisfying"
		fromAdmissionLevel = "advisory"
	}
	return map[string]any{
		"schemaVersion":        1,
		"admissionChanges":     []any{admissionChange(changeKind, fromAdmissionLevel, toAdmissionLevel)},
		"baselinePolicyDigest": digestText(),
		"guardId":              "proofkit.policy.guard",
		"mergeObligationReceiptRefs": []any{
			map[string]any{
				"artifactRetentionRuleRef": "docs/policy/artifacts.md",
				"environmentClass":         "local-go",
				"evidenceRef":              "artifacts/test/report.json",
				"nonClaim":                 "Synthetic receipt ref for self-proof test.",
				"nonClaimRefs":             []any{"NC-POLICY-001"},
				"producerAdmissionClass":   receiptAdmissionClass,
				"producerClass":            "ci",
				"producerId":               "github.actions.package",
				"proofClass":               "package-gate",
				"proofReceiptDigest":       digestText(),
				"proofReceiptRef":          "artifacts/test/receipt.json",
				"provenanceRuleRef":        "docs/policy/provenance.md",
				"receiptId":                "receipt.test.policy",
				"receiptKind":              "proofkit.package",
				"receiptStatus":            "passed",
				"satisfiesMergeObligation": true,
				"usedForPolicyChangeId":    "proofkit.policy.change",
			},
		},
		"nonClaimRefs":         []any{"NC-POLICY-001"},
		"nonClaims":            []any{"Synthetic policy input does not authenticate producers."},
		"policyChangeDigest":   digestText(),
		"policyChangeId":       "proofkit.policy.change",
		"policyId":             "proofkit.policy",
		"policyOwner":          "proofkit.test",
		"policySurfaceRefs":    []any{"proofkit/receipt-producer-policy.json"},
		"proposedPolicyDigest": "sha256:" + strings.Repeat("b", 64),
	}
}

func admissionChange(changeKind string, fromAdmissionLevel any, toAdmissionLevel string) map[string]any {
	return map[string]any{
		"artifactRetentionRuleRef": "docs/policy/artifacts.md",
		"changeId":                 "proofkit.policy.change.001",
		"changeKind":               changeKind,
		"environmentClass":         "local-go",
		"evidenceRefs":             []any{"docs/policy/evidence.md"},
		"fromAdmissionLevel":       fromAdmissionLevel,
		"nonClaim":                 "Synthetic policy change for self-proof test.",
		"nonClaimRefs":             []any{"NC-POLICY-001"},
		"producerClass":            "ci",
		"producerId":               "github.actions.package",
		"proofClass":               "package-gate",
		"provenanceRuleRef":        "docs/policy/provenance.md",
		"receiptKind":              "proofkit.package",
		"toAdmissionLevel":         toAdmissionLevel,
	}
}

func cloneMap(t *testing.T, input map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal clone: %v", err)
	}
	var output map[string]any
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatalf("unmarshal clone: %v", err)
	}
	return output
}

func digestText() string {
	return "sha256:" + strings.Repeat("a", 64)
}
