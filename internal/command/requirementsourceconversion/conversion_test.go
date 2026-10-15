package requirementsourceconversion

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

// The fixtures are hand-authored: source.grouped.json is canonical grouped
// codec output with non-ASCII text spelled as JSON escapes, and source.flat.json
// states its expected flat document field by field. basisDigest is checked
// with crypto/sha256 over the codec's canonical bytes, not with the
// converter's digest helper.
func TestConversionMatchesHandAuthoredDocuments(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.111746205776408057136581918812670444885484827234300308233326369821488047472385")
	groupedBytes := fixtureBytes(t, "source.grouped.json")
	canonical, err := requirementsourcecodec.Format(groupedModel(t, decode(t, groupedBytes)))
	if err != nil || asciiEscaped(canonical) != string(groupedBytes) {
		t.Fatalf("grouped fixture is not the ASCII-escaped canonical codec output: %v", err)
	}
	sum := sha256.Sum256(canonical)
	expectedFlat := fixture(t, "source.flat.json")
	if expectedFlat["basisDigest"] != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("hand-authored basisDigest is not the sha256 of the canonical grouped source")
	}

	flat, err := ExportFlat(decode(t, groupedBytes))
	if err != nil {
		t.Fatal(err)
	}
	if canonicalJSON(t, flat) != canonicalJSON(t, expectedFlat) {
		t.Fatalf("export differs from the hand-authored flat document:\n got %s\nwant %s", canonicalJSON(t, flat), canonicalJSON(t, expectedFlat))
	}

	grouped, err := ImportFlat(fixture(t, "source.flat.json"), decode(t, groupedBytes))
	if err != nil {
		t.Fatal(err)
	}
	if canonicalJSON(t, grouped) != canonicalJSON(t, decode(t, groupedBytes)) {
		t.Fatalf("import differs from the hand-authored grouped source:\n got %s", canonicalJSON(t, grouped))
	}
	if !sameModel(groupedModel(t, grouped), groupedModel(t, decode(t, groupedBytes))) {
		t.Fatal("import does not preserve the full model")
	}
}

// A flat document alone carries every ownership coordinate; the baseline is a
// freshness and authority check, not a source of missing facts.
func TestFlatDocumentAloneReconstructsTheCompleteModel(t *testing.T) {
	reconstruction, err := readFlat(fixture(t, "source.flat.json"))
	if err != nil {
		t.Fatal(err)
	}
	expected := groupedModel(t, fixture(t, "source.grouped.json"))
	if !reflect.DeepEqual(reconstruction.model.Atomic(), expected.Atomic()) {
		t.Fatal("resolved values differ")
	}
	if !reflect.DeepEqual(reconstruction.model.Layout(), expected.Layout()) {
		t.Fatal("ownership layout differs")
	}
	if !reflect.DeepEqual(reconstruction.model.References(), expected.References()) {
		t.Fatal("references differ")
	}
}

// Equal resolved values never imply shared ownership: ownerId has the same
// value in two groups, owned by a profile in one and by members in the other.
func TestIdenticalValuesKeepTheirDistinctOwners(t *testing.T) {
	grouped, err := ImportFlat(fixture(t, "source.flat.json"), fixture(t, "source.grouped.json"))
	if err != nil {
		t.Fatal(err)
	}
	owners := map[string]requirementsourcemodel.FieldOwner{}
	for _, origin := range groupedModel(t, grouped).Layout().Origins {
		for _, owner := range origin.FieldOwners {
			if owner.FieldID == "ownerId" {
				owners[origin.RequirementID] = owner
			}
		}
	}
	want := map[string]requirementsourcemodel.FieldOwner{
		"REQ-CONV-001": {FieldID: "ownerId", OwnerKind: requirementsourcemodel.MetadataOwnerProfile, OwnerID: "RPROF-CONV-BLOCKING"},
		"REQ-CONV-002": {FieldID: "ownerId", OwnerKind: requirementsourcemodel.MetadataOwnerProfile, OwnerID: "RPROF-CONV-BLOCKING"},
		"REQ-CONV-003": {FieldID: "ownerId", OwnerKind: requirementsourcemodel.MetadataOwnerMember, OwnerID: "REQ-CONV-003"},
		"REQ-CONV-004": {FieldID: "ownerId", OwnerKind: requirementsourcemodel.MetadataOwnerMember, OwnerID: "REQ-CONV-004"},
		"REQ-CONV-005": {FieldID: "ownerId", OwnerKind: requirementsourcemodel.MetadataOwnerMember, OwnerID: "REQ-CONV-005"},
		"REQ-CONV-006": {FieldID: "ownerId", OwnerKind: requirementsourcemodel.MetadataOwnerMember, OwnerID: "REQ-CONV-006"},
	}
	if !reflect.DeepEqual(owners, want) {
		t.Fatalf("ownerId owners = %#v", owners)
	}
}

// Caller order of groups, members, sets and sections is not part of the
// model, so export is a function of the model alone.
func TestExportIsIndependentOfCallerOrder(t *testing.T) {
	expected := canonicalJSON(t, fixture(t, "source.flat.json"))
	reordered := fixture(t, "source.grouped.json")
	groups := at(t, reordered, "/groups").([]any)
	slices.Reverse(groups)
	for _, group := range groups {
		slices.Reverse(group.(map[string]any)["members"].([]any))
	}
	slices.Reverse(at(t, reordered, "/profiles").([]any))
	slices.Reverse(at(t, reordered, "/nonClaimDefinitions").([]any))
	slices.Reverse(at(t, reordered, "/derivations/0/requirementIds").([]any))
	slices.Reverse(at(t, reordered, "/scenarios/0/examples").([]any))
	unicode := groups[0].(map[string]any)
	if unicode["groupId"] != "RGRP-CONV-UNICODE" {
		t.Fatal("fixture order changed")
	}
	slices.Reverse(unicode["sharedPremises"].([]any))
	for attempt := 0; attempt < 3; attempt++ {
		flat, err := ExportFlat(clone(t, reordered))
		if err != nil {
			t.Fatal(err)
		}
		if canonicalJSON(t, flat) != expected {
			t.Fatalf("attempt %d: export depends on caller order", attempt)
		}
	}
}

// Export and import compose to the identity on the model and are idempotent on
// emitted documents.
func TestRoundTripsAreIdempotent(t *testing.T) {
	grouped := fixture(t, "source.grouped.json")
	first, err := ExportFlat(clone(t, grouped))
	if err != nil {
		t.Fatal(err)
	}
	imported, err := ImportFlat(clone(t, first), clone(t, grouped))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExportFlat(clone(t, imported))
	if err != nil {
		t.Fatal(err)
	}
	if canonicalJSON(t, first) != canonicalJSON(t, second) {
		t.Fatal("export of the imported source differs from the first export")
	}
	again, err := ImportFlat(clone(t, second), clone(t, imported))
	if err != nil {
		t.Fatal(err)
	}
	if canonicalJSON(t, again) != canonicalJSON(t, imported) {
		t.Fatal("second import differs from the first")
	}
}

// Every self-hosted grouped source converts both ways to the same model, and
// canonical sources come back byte for byte through the grouped codec.
func TestSelfHostedSourcesRoundTrip(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "docs", "specs", "*", "requirements.v2.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("self-hosted sources: %v %v", paths, err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			flat, err := ExportFlat(decode(t, data))
			if err != nil {
				t.Fatal(err)
			}
			grouped, err := ImportFlat(clone(t, flat), decode(t, data))
			if err != nil {
				t.Fatal(err)
			}
			original := groupedModel(t, decode(t, data))
			converted := groupedModel(t, grouped)
			if !sameModel(original, converted) {
				t.Fatal("round trip changed the model")
			}
			canonical, err := requirementsourcecodec.Format(converted)
			if err != nil {
				t.Fatal(err)
			}
			if originalCanonical, _ := requirementsourcecodec.Format(original); string(canonical) != string(originalCanonical) {
				t.Fatal("round trip changed canonical bytes")
			}
		})
	}
}

// The flat record inventory is exactly the model's metadata field inventory,
// so a new model field cannot be silently omitted from flat records.
func TestFlatFieldInventoryMatchesTheModel(t *testing.T) {
	model := groupedModel(t, fixture(t, "source.grouped.json"))
	for _, origin := range model.Layout().Origins {
		names := make([]string, len(origin.FieldOwners))
		for index, owner := range origin.FieldOwners {
			names[index] = string(owner.FieldID)
		}
		slices.Sort(names)
		if !slices.Equal(names, flatFieldIDs) {
			t.Fatalf("%s field owners %v differ from flat inventory %v", origin.RequirementID, names, flatFieldIDs)
		}
	}
}

// The export join requires the model's exclusive and total partition; an
// overlap or a gap is refused instead of letting one owner shadow another.
func TestResolvedFieldsRequireTheExclusiveTotalPartition(t *testing.T) {
	profile := map[string]any{"claimLevel": "blocking", "ownerId": "owner", "riskClass": "high", "updatePolicy": map[string]any{"reviewOwnerId": "owner"}}
	member := map[string]any{"deferral": nil, "externalNonClaimRefs": values(), "lifecycle": map[string]any{"state": "active"}, "nonClaimRefs": values(), "nonClaims": values(), "proofBindingRefs": values()}
	if fields, ok := resolvedFields(profile, member); !ok || len(fields) != len(flatFieldIDs) {
		t.Fatalf("partition join = %v %v", fields, ok)
	}
	overlap := clone(t, member)
	overlap["ownerId"] = "member"
	gap := clone(t, member)
	delete(gap, "nonClaims")
	for name, candidate := range map[string]map[string]any{"overlap": overlap, "gap": gap} {
		if _, ok := resolvedFields(profile, candidate); ok {
			t.Fatalf("%s was joined", name)
		}
	}
}

// Declared units: ns/op, B/op and allocs/op per conversion of the largest
// self-hosted source, plus the canonical grouped and compact flat byte sizes
// as payload metrics. Timing is machine-dependent and not a public bound.
func BenchmarkSpecProofCoreConversion(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "specs", "proofkit-spec-proof-core", "requirements.v2.json"))
	if err != nil {
		b.Fatal(err)
	}
	grouped, err := admission.DecodeJSON(bytes.NewReader(data), fixtureBytesLimit)
	if err != nil {
		b.Fatal(err)
	}
	flat, err := ExportFlat(grouped)
	if err != nil {
		b.Fatal(err)
	}
	flatBytes, err := stablejson.MarshalLayout(flat, stablejson.LayoutCompact)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("export", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := ExportFlat(grouped); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(len(data)), "grouped-bytes")
	})
	b.Run("import", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := ImportFlat(flat, grouped); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(len(flatBytes)), "flat-bytes")
	})
}

// asciiEscaped spells every non-ASCII rune of canonical JSON text as a JSON
// escape, the repository's ASCII-only fixture spelling of the same value.
func asciiEscaped(text []byte) string {
	var builder strings.Builder
	for _, character := range string(text) {
		if character < utf8.RuneSelf {
			builder.WriteRune(character)
			continue
		}
		for _, unit := range utf16.Encode([]rune{character}) {
			fmt.Fprintf(&builder, "\\u%04x", unit)
		}
	}
	return builder.String()
}
