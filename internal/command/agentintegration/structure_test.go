package agentintegration

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func integrationWireValue(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	return decoded.(map[string]any)
}

func integrationShapeAccepts(t *testing.T, shape jsonshape.Shape, value map[string]any, want bool) {
	t.Helper()
	_, err := shape.Admit(value, "integration output specimen")
	if (err == nil) != want {
		t.Fatalf("structural admission success=%v, want %v: %v", err == nil, want, err)
	}
}

func TestIntegrationOutputShapesPreserveNativeValuesAndPhaseHeaders(t *testing.T) {
	for _, tool := range Tools() {
		t.Run(tool, func(t *testing.T) {
			document, err := Source(tool, sourceCapabilities())
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			check, err := Check(context.Background(), root, document)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := PlanLifecycle(context.Background(), root, document, OperationInstall)
			if err != nil {
				t.Fatal(err)
			}
			applied, err := ApplyLifecycle(context.Background(), root, document, OperationInstall, plan.transaction.TransactionID, plan.transaction.DesiredStateID)
			if err != nil {
				t.Fatal(err)
			}
			recovered := LifecycleReceipt{operation: OperationRecover, expectedTransactionID: plan.transaction.TransactionID, state: "blocked", failure: "transaction_busy"}
			for _, row := range []struct {
				name   string
				shape  jsonshape.Shape
				value  any
				fields []string
			}{
				{"source", SourceOutputShape(), document.JSONValue(), []string{"bodyBytes", "capabilityDigest", "content", "contentDigest", "integrationId", "kind", "metadataBytes", "nonClaims", "schemaVersion", "targetPath", "tool"}},
				{"check", CheckOutputShape(), check.JSONValue(), []string{"expectedContentDigest", "integrationId", "kind", "nonClaims", "schemaVersion", "state", "targetPath", "tool"}},
				{"plan", PlanOutputShape(), plan.JSONValue(), []string{"failureClass", "kind", "nonClaims", "operation", "recoveryTransactionId", "schemaVersion", "state", "tool", "transaction"}},
				{"apply", ApplyOutputShape(), applied.JSONValue(), []string{"expectedDesiredStateId", "expectedTransactionId", "failureClass", "kind", "nonClaims", "operation", "schemaVersion", "state", "tool", "transactionResult"}},
				{"recover", RecoverOutputShape(), recovered.JSONValue(), []string{"expectedDesiredStateId", "expectedTransactionId", "failureClass", "kind", "nonClaims", "operation", "schemaVersion", "state", "tool", "transactionResult"}},
			} {
				t.Run(row.name, func(t *testing.T) {
					value := integrationWireValue(t, row.value)
					keys := make([]string, 0, len(value))
					for key := range value {
						keys = append(keys, key)
					}
					slices.Sort(keys)
					if !slices.Equal(keys, row.fields) {
						t.Fatalf("native field inventory differs: %v", keys)
					}
					integrationShapeAccepts(t, row.shape, value, true)
					if value["schemaVersion"] != json.Number("1") {
						t.Fatal("outer wire version drift")
					}
					for _, key := range row.fields {
						missing := integrationWireValue(t, value)
						delete(missing, key)
						integrationShapeAccepts(t, row.shape, missing, false)
						wrong := integrationWireValue(t, value)
						wrong[key] = map[string]any{"unexpected": true}
						integrationShapeAccepts(t, row.shape, wrong, false)
					}
					value["unexpected"] = true
					integrationShapeAccepts(t, row.shape, value, false)
				})
			}
			if recovered.JSONValue()["tool"] != nil || recovered.JSONValue()["expectedDesiredStateId"] != nil {
				t.Fatal("recovery acquired current tool/desired authority")
			}
		})
	}
}

func TestIntegrationOutputShapesSeparateFieldDomains(t *testing.T) {
	document, err := Source("codex", sourceCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	source := integrationWireValue(t, document.JSONValue())
	check := integrationWireValue(t, (CheckResult{document: document, state: "current"}).JSONValue())
	plan := integrationWireValue(t, (LifecyclePlan{document: document, operation: "install", state: "blocked"}).JSONValue())
	apply := integrationWireValue(t, (LifecycleReceipt{tool: "codex", operation: "install", state: "blocked", expectedTransactionID: digest, expectedDesiredStateID: digest}).JSONValue())
	recover := integrationWireValue(t, (LifecycleReceipt{operation: "recover", state: "blocked", expectedTransactionID: digest}).JSONValue())
	for _, row := range []struct {
		shape jsonshape.Shape
		value map[string]any
		enums map[string][]string
	}{
		{SourceOutputShape(), source, nil},
		{CheckOutputShape(), check, map[string][]string{"state": {"missing", "invalid", "stale", "current"}}},
		{PlanOutputShape(), plan, map[string][]string{"state": {"ready", "blocked", "recovery_required"}, "operation": {"install", "remove", "update"}}},
		{ApplyOutputShape(), apply, map[string][]string{"state": {"passed", "blocked", "failed", "recovery_required", "cleanup_required", "durability_unknown"}, "operation": {"install", "remove", "update"}, "tool": {"claude", "codex"}}},
		{RecoverOutputShape(), recover, map[string][]string{"state": {"passed", "blocked", "failed", "recovery_required", "cleanup_required", "durability_unknown"}}},
	} {
		integrationShapeAccepts(t, row.shape, row.value, true)
		for field, members := range row.enums {
			for _, member := range append(slices.Clone(members), "foreign") {
				changed := integrationWireValue(t, row.value)
				changed[field] = member
				integrationShapeAccepts(t, row.shape, changed, member != "foreign")
			}
		}
		for field, original := range row.value {
			changed := integrationWireValue(t, row.value)
			switch field {
			case "schemaVersion":
				changed[field] = json.Number("2")
			case "kind":
				changed[field] = "proofkit.foreign.v1"
			default:
				text, ok := original.(string)
				if !ok || !strings.HasPrefix(text, "sha256:") {
					continue
				}
				for _, bad := range []string{"sha256:" + strings.Repeat("A", 64), text[:len(text)-1], text + "0", "sha255:" + strings.Repeat("a", 64), "SHA256:" + strings.Repeat("a", 64), " " + text, text + "\n"} {
					changed[field] = bad
					integrationShapeAccepts(t, row.shape, changed, false)
				}
				continue
			}
			integrationShapeAccepts(t, row.shape, changed, false)
		}
		claims := row.value["nonClaims"].([]any)
		for i := range claims {
			changed := integrationWireValue(t, row.value)
			changed["nonClaims"].([]any)[i] = "A foreign denial."
			integrationShapeAccepts(t, row.shape, changed, false)
		}
		for _, length := range []int{len(claims) - 1, len(claims) + 1} {
			changed := integrationWireValue(t, row.value)
			extra := append(slices.Clone(claims), claims[0])
			changed["nonClaims"] = extra[:length]
			integrationShapeAccepts(t, row.shape, changed, false)
		}
	}
	for _, value := range []map[string]any{source, check} {
		shape := SourceOutputShape()
		if value["kind"] == "proofkit.integration-check.v1" {
			shape = CheckOutputShape()
		}
		value["targetPath"] = ".claude/skills/agentic-proofkit/SKILL.md"
		integrationShapeAccepts(t, shape, value, false)
		value["tool"] = "claude"
		integrationShapeAccepts(t, shape, value, true)
		value["tool"] = "foreign"
		integrationShapeAccepts(t, shape, value, false)
	}
	for _, field := range []string{"tool", "expectedDesiredStateId"} {
		changed := integrationWireValue(t, recover)
		changed[field] = digest
		integrationShapeAccepts(t, RecoverOutputShape(), changed, false)
	}
	recover["operation"] = "install"
	integrationShapeAccepts(t, RecoverOutputShape(), recover, false)
}

func TestIntegrationSourceBoundsAndRawContentFraming(t *testing.T) {
	document, err := Source("codex", sourceCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	value := integrationWireValue(t, document.JSONValue())
	for _, count := range []json.Number{"1", "4096", "0", "4097", "-1", "1.5"} {
		value["bodyBytes"] = count
		integrationShapeAccepts(t, SourceOutputShape(), value, count == "1" || count == "4096")
	}
	value["bodyBytes"] = json.Number("1")
	for _, content := range []string{"x", "\nx\n", strings.Repeat("x", 4608), "", strings.Repeat("x", 4609)} {
		value["content"] = content
		integrationShapeAccepts(t, SourceOutputShape(), value, content != "" && len(content) <= 4608)
	}
	value = integrationWireValue(t, document.JSONValue())
	value["metadataBytes"] = json.Number("0")
	integrationShapeAccepts(t, SourceOutputShape(), value, false)
	first := SourceOutputStructure()
	first["oneOf"].([]any)[0].(map[string]any)["properties"].(map[string]any)["foreign"] = true
	if reflect.DeepEqual(first, SourceOutputStructure()) {
		t.Fatal("shared mutable output structure")
	}
}
