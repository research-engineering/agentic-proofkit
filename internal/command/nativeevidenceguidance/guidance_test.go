package nativeevidenceguidance

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

var slotFingerprints = [...]string{
	"4f7d1ea4203b97065c619f024d88f3f1fb1eb3df8c022a7cab69ad8af0b0d251",
	"1b6b182ab32c13c303bb31cab396112256daa9d7361ef99f6cc7af6fc088fa81",
	"45df453e81d723ccef3cf29eb3ccde7ba90bac72356194e49ba19f26fc252fd1",
	"555d5b05c5588974c86b471dfd9af8ee9b4774ee75ff981a5148902fa9974ba8",
	"80c46416ff3b4855c832b1c126180e4c0d630265a814f47874ab4a99e752a9fa",
	"ecf29279f0527277c0ea62aa5210917659743357d17b88696175cd85a513c6fb",
	"fed68d4a0833735bff84ab5509dfc07a233611aa7c3ca2593efdb2fe6de31f46",
	"5f76850ecd6571cc081365656f89e4888bf6ce53f6f47efceaebb8e83f271427",
	"8adea3ac35394b6bebf904f51a1a488cad8d156713566076c8ba529e36b725d8",
	"e7ca629cbe625bb8c342dfadb1ca9ecb3e4456d7dbe394e3bf7e158b5ed8d048",
	"ed669cec6efc72612632050c1173395741290639e9bca106352276212e387a0e",
	"4f72cdb349f7d87a8a25ce0c6180dd403224792c710b274b9b393d6c3b64cf93",
	"d5883acd09e114ca0571af5c845c9770e31b11178d59aa3bcebeead8e8ad7e51",
	"d2f65a835de4d04ed0d8d5b322ab694a26ff68f85055d4a13790ea13e45bb6b8",
	"d5a74ef4e8e16ee74991962d72871787e92508b32e2460344e99f87c87950aaf",
	"df63e39402c6daa6aa078e18e75d741da855f9490c7d4cfad3dbcbef37aa1b55",
	"10ef4f5cbc7b81d12479bb1b2c48be1d59349e40ca0859e23fd0376bca6279de",
	"6d63c32605c2a21ae866e7edfb1dc6b9c752e5e87987d6cf8d62627e8f0f78d4",
	"833a7d9fb8309efce8b1ad5c728fe7c393ae5d90cdfd50a71e88df3acab731e2",
	"c6caf7c6e81f0aab3b4261fde6c490d46cc3db0cc3869d79dbad44553e913f7a",
	"6c83ba103d8c1b4ad61d196bc90bd8c6033c3b7b35173efbc6b7be8e192cc3bb",
	"05ed48165f9ef51ca30d2f0cad31050cd65beca08dca56ced734e27dca35711c",
}

func TestGuidanceSlotPredicates(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.011574335775061433824546899357885119356867940503348997935121282242720220286828")
	guidance, err := Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if guidance.SchemaVersion != SchemaVersion || guidance.GuidanceID != GuidanceID || len(guidance.Slots) != SlotCount {
		t.Fatalf("Build() = %#v, want fixed versioned 22-slot guidance", guidance)
	}
	for _, slot := range guidance.Slots {
		slot := slot
		t.Run("slot_"+slot.SlotID, func(t *testing.T) {
			if got, want := slotFingerprint(slot), slotFingerprints[slot.Order-1]; got != want {
				t.Fatalf("slot %s fingerprint = %s, want %s", slot.SlotID, got, want)
			}
		})
	}
}

func TestGuidancePurityPredicates(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.058757478738758052674807161936434157865458879934093996636398118539163086073405")
	t.Run("deterministic_rebuild", func(t *testing.T) {
		first, err := Build()
		if err != nil {
			t.Fatalf("first Build() error = %v", err)
		}
		first.Slots[0].SlotID = "mutated"
		first.NonClaims[0] = "mutated"
		second, err := Build()
		if err != nil {
			t.Fatalf("second Build() error = %v", err)
		}
		if second.Slots[0].SlotID == "mutated" || second.NonClaims[0] == "mutated" {
			t.Fatalf("Build() leaked mutable state: %#v", second)
		}
		firstText, err := RenderPlainText()
		if err != nil {
			t.Fatalf("first RenderPlainText() error = %v", err)
		}
		secondText, err := RenderPlainText()
		if err != nil {
			t.Fatalf("second RenderPlainText() error = %v", err)
		}
		if firstText != secondText {
			t.Fatal("RenderPlainText() is not deterministic")
		}
	})

}

func TestGuidancePlainTextIsBoundedAndComplete(t *testing.T) {
	text, err := RenderPlainText()
	if err != nil {
		t.Fatalf("RenderPlainText() error = %v", err)
	}
	if len(text) > MaximumTextBytes || strings.Count(text, "\n") > MaximumTextLines {
		t.Fatalf("text bounds exceeded: bytes=%d lines=%d", len(text), strings.Count(text, "\n"))
	}
	guidance, err := Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	for _, slot := range guidance.Slots {
		for _, required := range []string{slot.SlotID, slot.RequiredConsumerDecision, slot.CompletionCriterion} {
			if !strings.Contains(text, required) {
				t.Fatalf("text omits required slot projection %q", required)
			}
		}
	}
}

func TestGuidanceTextProjectionOwnsPlainTextBytes(t *testing.T) {
	lines, err := TextProjection()
	if err != nil {
		t.Fatalf("TextProjection() error = %v", err)
	}
	if got, want := len(lines), SlotCount*2+1; got != want {
		t.Fatalf("TextProjection() line count = %d, want %d", got, want)
	}
	var projected strings.Builder
	for _, line := range lines {
		if line.Label == "" || line.Value == "" {
			t.Fatalf("empty text coordinate: %#v", line)
		}
		projected.WriteString(line.Label)
		projected.WriteString(": ")
		projected.WriteString(line.Value)
		projected.WriteByte('\n')
	}
	plain, err := RenderPlainText()
	if err != nil {
		t.Fatalf("RenderPlainText() error = %v", err)
	}
	if projected.String() != plain {
		t.Fatalf("structured text projection drifted from plain bytes")
	}
}

func TestGuidanceJSONProjectionIsFreshAndComplete(t *testing.T) {
	guidance, err := Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	first := guidance.JSONValue()
	firstSlots := first["slots"].([]any)
	firstSlots[0].(map[string]any)["slotId"] = "mutated"
	first["nonClaims"].([]any)[0] = "mutated"
	second := guidance.JSONValue()
	secondSlots := second["slots"].([]any)
	if secondSlots[0].(map[string]any)["slotId"] != guidance.Slots[0].SlotID || second["nonClaims"].([]any)[0] != guidance.NonClaims[0] {
		t.Fatalf("JSONValue leaked mutable projection state: %#v", second)
	}
	if got, want := len(secondSlots), SlotCount; got != want {
		t.Fatalf("JSONValue slot count = %d, want %d", got, want)
	}
}

func slotFingerprint(slot Slot) string {
	value := fmt.Sprintf("%d\x1f%s\x1f%s\x1f%s\x1f%s", slot.Order, slot.SlotID, slot.Question, slot.RequiredConsumerDecision, slot.CompletionCriterion)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
}
