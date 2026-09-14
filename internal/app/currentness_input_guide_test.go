package app

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

// This is the fixture consumer's mapping policy, not a public receipt adapter.
func checkCurrentnessGuideReceiptHandoff(t *testing.T, receipts, binding map[string]any, root string) {
	t.Helper()
	input, help := receiptHelpTemplate(t, "receipt-currentness-scope")
	args := fillGuideOperands(t, guideCommands(t, help, "Receipt currentness input guide:", cliexec.PathRenderer())[0], map[string]string{"<currentness-input>": "-"})
	r := receipt(receipts)
	var bound map[string]any
	for _, raw := range binding["bindings"].([]any) {
		row := raw.(map[string]any)
		if slices.Contains(row["commandIds"].([]any), r["receiptKind"]) && slices.Contains(r["witnessSelectors"].([]any), row["scenarioId"]) {
			bound = row
			break
		}
	}
	if bound == nil {
		t.Fatal("fixture has no qualified binding for the receipt")
	}
	var owner any
	for _, raw := range binding["requirements"].([]any) {
		row := raw.(map[string]any)
		if row["requirementId"] == bound["requirementId"] {
			owner = row["ownerId"]
		}
	}
	input["admissionId"] = "example.currentness"
	item := input["obligationReceipts"].([]any)[0].(map[string]any)
	identity := map[string]any{
		"receiptId": r["receiptId"], "requirementId": bound["requirementId"], "proofRouteRef": r["receiptKind"],
		"owner": owner, "obligationId": "example.obligation",
	}
	for key, value := range identity {
		item[key] = value
	}
	item["reason"] = "Compare retained fixture subjects under explicit consumer policy."
	item["evidenceRefs"] = r["evidenceRefs"]
	checks := []any{}
	recorded := map[string]any{}
	fields := []string{"commandDigest", "environmentDigest", "preconditionDigest", "proofBindingDigest", "toolchainDigest", "witnessSelectorDigest"}
	for index, field := range fields {
		data, err := os.ReadFile(filepath.Join(root, field+".json"))
		if err != nil {
			t.Fatal(err)
		}
		actual := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
		if actual != r[field] {
			t.Fatal("retained bytes are not the receipt's recorded subject: " + field)
		}
		checks = append(checks, map[string]any{
			"checkId": fmt.Sprintf("example.check.%d", index), "checkClass": field,
			"recordedDigest": r[field], "currentDigest": actual,
			"evidenceRefs": []any{field + ".json"}, "nonClaims": []any{"Synthetic consumer capture is not authenticated."},
		})
		recorded[field] = r[field]
	}
	item["currentnessChecks"] = checks
	scope := item["scopeChecks"].([]any)[0].(map[string]any)
	for key, value := range map[string]any{
		"checkId": "example.scope", "scopeClass": "binding_scope", "admissionState": "admitted_current_scope",
		"recordedScopeDigest": r["proofBindingDigest"], "currentScopeDigest": r["proofBindingDigest"],
		"reason": "The fixture retains the same admitted binding scope.", "evidenceRefs": []any{"proofBindingDigest.json"},
	} {
		scope[key] = value
	}
	if !currentnessGuideHandoffMatches(item, identity, recorded) {
		t.Fatal("receipt-to-currentness handoff lost identity or recorded operands")
	}
	for _, mutation := range []string{"receipt", "recorded"} {
		wrong := cloneMap(t, item)
		if mutation == "receipt" {
			wrong["receiptId"] = "example.other-receipt"
		} else {
			wrong["currentnessChecks"].([]any)[0].(map[string]any)["recordedDigest"] = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("foreign recorded subject")))
		}
		if currentnessGuideHandoffMatches(wrong, identity, recorded) {
			t.Fatalf("consumer mapping accepted a substituted %s", mutation)
		}
	}
	positive := currentnessGuideReport(t, args, input, 0)
	assertGuideCount(t, positive, "currentReceiptCount", 1)
	assertGuideCount(t, positive, "staleReceiptCount", 0)
	for index, field := range fields {
		data, err := os.ReadFile(filepath.Join(root, field+".json"))
		if err != nil {
			t.Fatal(err)
		}
		changed := cloneMap(t, input)
		current := changed["obligationReceipts"].([]any)[0].(map[string]any)["currentnessChecks"].([]any)[index].(map[string]any)
		subject := decodeCLIJSON(t, string(data))
		switch field {
		case "commandDigest":
			subject.(map[string]any)["cwd"] = root + "-changed"
		case "environmentDigest":
			subject.(map[string]any)["class"] = "ci-go"
		case "preconditionDigest":
			subject.(map[string]any)["syntheticPolicy"] = false
		case "proofBindingDigest":
			subject.(map[string]any)["bindingId"] = "example.changed-binding"
		case "toolchainDigest", "witnessSelectorDigest":
			subject.([]any)[0] = "example.changed"
		}
		current["currentDigest"] = fmt.Sprintf("sha256:%x", sha256.Sum256(adoptionHelpJSON(t, subject)))
		result := currentnessGuideReport(t, args, changed, 1)
		assertGuideCount(t, result, "staleReceiptCount", 1)
		assertGuideCount(t, result, "scopeFindingCount", 0)
	}
	for _, state := range []string{"not_admitted_current_scope", "unknown_current_scope", "not_applicable", "scope_digest"} {
		changed := cloneMap(t, input)
		changedScope := changed["obligationReceipts"].([]any)[0].(map[string]any)["scopeChecks"].([]any)[0].(map[string]any)
		wantCode := 1
		if state == "scope_digest" {
			changedScope["currentScopeDigest"] = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("independent changed scope")))
		} else {
			changedScope["admissionState"] = state
		}
		if state == "not_applicable" {
			wantCode = 0
		}
		result := currentnessGuideReport(t, args, changed, wantCode)
		assertGuideCount(t, result, "staleReceiptCount", 0)
		if state == "not_applicable" {
			assertGuideCount(t, result, "notApplicableCount", 1)
			if result["ruleResults"].([]any)[0].(map[string]any)["status"] != "skipped" {
				t.Fatal("inapplicability became a passing rule")
			}
		} else {
			assertGuideCount(t, result, "unknownScopeCount", 1)
			assertGuideCount(t, result, "scopeFindingCount", 1)
		}
	}
	if restored := currentnessGuideReport(t, args, input, 0); !reflect.DeepEqual(positive, restored) {
		t.Fatal("restored subjects did not recover the positive result")
	}
}

func currentnessGuideHandoffMatches(item, identity, recorded map[string]any) bool {
	for key, value := range identity {
		if !reflect.DeepEqual(item[key], value) {
			return false
		}
	}
	actual := map[string]any{}
	for _, raw := range item["currentnessChecks"].([]any) {
		check := raw.(map[string]any)
		class := check["checkClass"].(string)
		if _, exists := actual[class]; exists {
			return false
		}
		actual[class] = check["recordedDigest"]
	}
	return reflect.DeepEqual(actual, recorded)
}
