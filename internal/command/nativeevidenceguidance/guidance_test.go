package nativeevidenceguidance

import (
	"crypto/sha256"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

var slotFingerprints = [...]string{
	"8c9fb4466291b8a60aeed04ffe91e684753424bb71cf93ba0eb7c73ae31b5d21",
	"f68141d84607e4f343982c753116bb0aeba8e4fcbc65a25cb0284548ac95853c",
	"930d361a8fde04b1391f2040254efa3c8ae30506a08776072955645d233f53c6",
	"11e011fe5d90085990ef5837ae40b5d1c179ba787f56d544d855c1fd29324844",
	"62b191cc9e5752295aa04c16aab4bbbf67be9ba67893ebae7b9a3d47b1e9542c",
	"e214e2c6203145b94a43f0f4992fd3b40232f439acbd7a17ec3de22da73c9dd8",
	"b9f830de4358ce0976002226a55d3e21479a7a02b8e6a6d28e2cba58d7222095",
	"4b34d7c224d13957e333ca1aa7eaac1d5ff19b5b54dfc8fb436f6e20fc735e25",
	"f45e880bad5b6f8e14a1d4f321ddcfdbefa83a143732c0b961459edb202c15e8",
	"f70d28729dc5589400787d398f868225f010bb159c822e57494ddfcffb3227af",
	"04a4843479b418e0f09d45077136bbd07c7b58b8e3f7143d045796051fc0e46f",
	"496e80d2cdfc106b0c36d9032ea2d3671c83ab670c363959f7cb30e6ed4fe3cc",
	"5c05b800f6579a9f120be7e3563a9d4dd60ed74ff46cb58651df91762b3cfb0a",
	"9f186415e33a8899b6ab423c61f9889372d4cb5b5d30dff669152a5100c3d565",
	"0a2e2c9f6c4294f51f82fc0f131512e5926784a04f1028db1f744361e7693cf8",
	"c1efe0f8cc0aa87bc6c05bf4ce603ceae72acbba4b357b64c588e6d9b6bfc2a0",
	"e72db7215f074d0353c635af40bb14263a5f3a8de895af849a5bf679ff3adc04",
	"be53fb4f4f32e22557922b20c62b42a5f5b8dc645aba27b7caf9af9e88eda905",
	"b55ed27e5e8dc19dfb7ae997d35b0566e55140bf75570f6b2e2a46b3ae84852b",
	"fc0065447b033670bb33c6be89d0080aa0ce7f0e60c4e74f7b24f46ec3a49119",
	"a7aa8e953573653e9c6f4924ba5205a65c61de6d9ff247d7048f082d0dab4e9d",
	"232e97077ee39087aebd1f2bc3baa5abdd1ff848f8f5779b5489be96b5668b50",
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
	actualFingerprints := make([]string, len(guidance.Slots))
	for index, slot := range guidance.Slots {
		actualFingerprints[index] = slotFingerprint(slot)
	}
	if !slices.Equal(actualFingerprints, slotFingerprints[:]) {
		t.Fatalf("slot fingerprints = %#v", actualFingerprints)
	}
	classCounts := map[string]int{}
	for _, slot := range guidance.Slots {
		classCounts[slot.ApplicabilityClass]++
	}
	wantClassCounts := map[string]int{
		ApplicabilityAlways:                15,
		ApplicabilityDeclaredInputChannels: 1,
		ApplicabilityEnvironmentOrNetwork:  1,
		ApplicabilityExternalProcess:       4,
		ApplicabilityMutableArtifacts:      1,
	}
	if !maps.Equal(classCounts, wantClassCounts) {
		t.Fatalf("applicability class partition = %#v, want %#v", classCounts, wantClassCounts)
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
		for _, required := range []string{slot.SlotID, slot.ApplicabilityClass, slot.RequiredConsumerDecision, slot.CompletionCriterion} {
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
	value := fmt.Sprintf("%d\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s", slot.Order, slot.SlotID, slot.ApplicabilityClass, slot.Question, slot.RequiredConsumerDecision, slot.CompletionCriterion)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
}
