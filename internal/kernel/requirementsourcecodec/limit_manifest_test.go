package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

type coefficientManifest struct {
	SchemaVersion             int               `json:"schemaVersion"`
	Kind                      string            `json:"kind"`
	CanonicalByteBaseOverhead int               `json:"canonicalByteBaseOverhead"`
	LexicalTokenBaseOverhead  int               `json:"lexicalTokenBaseOverhead"`
	MinimumJSONNesting        int               `json:"minimumJsonNesting"`
	MaximumJSONNesting        int               `json:"maximumJsonNesting"`
	CanonicalByteCoefficients []coefficientItem `json:"canonicalByteCoefficients"`
	LexicalTokenCoefficients  []coefficientItem `json:"lexicalTokenCoefficients"`
}

type coefficientItem struct {
	ID          string `json:"id"`
	Coefficient uint64 `json:"coefficient"`
}

func TestLimitCoefficientManifestMatchesProductionFormula(t *testing.T) {
	payload, err := os.ReadFile("testdata/codec-limit-coefficients.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := admission.DecodeTypedJSON[coefficientManifest](bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var strict coefficientManifest
	if err := decoder.Decode(&strict); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 1 || manifest.Kind != "proofkit.requirement-source-codec-limit-coefficients" ||
		manifest.CanonicalByteBaseOverhead != canonicalByteBaseOverhead || manifest.LexicalTokenBaseOverhead != lexicalTokenBaseOverhead ||
		manifest.MinimumJSONNesting != minimumJSONNesting || manifest.MaximumJSONNesting != defaultMaxNesting {
		t.Fatalf("coefficient manifest identity or constants mismatch: %#v", manifest)
	}
	limits := requirementsourcemodel.DefaultLimits()
	assertCoefficientRows(t, manifest.CanonicalByteCoefficients, canonicalByteCoefficients(limits))
	assertCoefficientRows(t, manifest.LexicalTokenCoefficients, lexicalTokenCoefficients(limits))
}

func TestLimitArithmeticRejectsOverflow(t *testing.T) {
	limits := requirementsourcemodel.DefaultLimits()
	maximumInt := int(^uint(0) >> 1)
	limits.MaxTotalTextBytes = maximumInt
	if _, err := MaxCanonicalBytes(limits); err == nil {
		t.Fatal("MaxCanonicalBytes() accepted overflowing limits")
	}
	limits = requirementsourcemodel.DefaultLimits()
	limits.MaxCollectionItems = maximumInt
	if _, err := MaxLexicalTokens(limits); err == nil {
		t.Fatal("MaxLexicalTokens() accepted overflowing limits")
	}
}

func TestCanonicalByteBoundCoversWorstAdmittedEscapeExpansion(t *testing.T) {
	for _, scalar := range []string{"\x00", "\u0085"} {
		t.Run(fmt.Sprintf("U+%04X", []rune(scalar)[0]), func(t *testing.T) {
			assertMaximalEscapedTextRoundTrip(t, scalar)
		})
	}
}

func assertMaximalEscapedTextRoundTrip(t *testing.T, scalar string) {
	t.Helper()
	assertMaximalTextRoundTrip(t, scalar, "text_budget_exceeded", func(draft *requirementsourcemodel.Draft, value string) {
		draft.NonClaimDefinitions[0].Statement = value
	})
}

func TestBoundaryMetadataMaximalTextPreservesPairedCodecLimits(t *testing.T) {
	t.Run("source", func(t *testing.T) {
		assertMaximalTextRoundTrip(t, "\x00", "text_budget_exceeded", func(draft *requirementsourcemodel.Draft, value string) {
			draft.SourceNonClaims = []string{value}
		})
	})
	for _, item := range []struct {
		name      string
		scalar    string
		limitCode string
		set       func(*requirementsourcemodel.MetadataFields, requirementsourcemodel.Field[[]string])
	}{
		{"nonClaims", "\x00", "text_budget_exceeded", func(fields *requirementsourcemodel.MetadataFields, value requirementsourcemodel.Field[[]string]) {
			fields.NonClaims = value
		}},
		{"externalNonClaimRefs", "a", "invalid_id", func(fields *requirementsourcemodel.MetadataFields, value requirementsourcemodel.Field[[]string]) {
			fields.ExternalNonClaimRefs = value
		}},
		{"proofBindingRefs", "a", "text_budget_exceeded", func(fields *requirementsourcemodel.MetadataFields, value requirementsourcemodel.Field[[]string]) {
			fields.ProofBindingRefs = value
		}},
	} {
		for _, owner := range []string{"member", "profile"} {
			t.Run(item.name+"/"+owner, func(t *testing.T) {
				assertMaximalTextRoundTrip(t, item.scalar, item.limitCode, func(draft *requirementsourcemodel.Draft, value string) {
					fields := &draft.Groups[0].Members[0].Fields
					if owner == "profile" {
						for index := range draft.Groups[0].Members {
							item.set(&draft.Groups[0].Members[index].Fields, requirementsourcemodel.Field[[]string]{})
						}
						fields = &draft.Profiles[0].Fields
					}
					item.set(fields, requirementsourcemodel.Own([]string{value}))
				})
			})
		}
	}
}

func assertMaximalTextRoundTrip(t *testing.T, scalar string, limitCode string, set func(*requirementsourcemodel.Draft, string)) {
	t.Helper()
	limits := compactTestModelLimits()
	low := 0
	high := limits.MaxTotalTextBytes/len(scalar) + 1
	for low+1 < high {
		middle := low + (high-low)/2
		draft := testDraft()
		set(&draft, "X"+strings.Repeat(scalar, middle)+"Y")
		if _, err := requirementsourcemodel.NormalizeWithLimits(draft, limits); err == nil {
			low = middle
		} else if requirementsourcemodel.ErrorCode(err) == limitCode {
			high = middle
		} else {
			t.Fatalf("boundary search encountered an unrelated rejection: %v", err)
		}
	}
	draft := testDraft()
	set(&draft, "X"+strings.Repeat(scalar, low)+"Y")
	model, err := requirementsourcemodel.NormalizeWithLimits(draft, limits)
	if err != nil {
		t.Fatalf("maximum admitted escape fixture error = %v", err)
	}
	codecLimits := pairedCodecLimits(t, limits)
	payload, err := FormatWithLimits(model, codecLimits, limits)
	if err != nil {
		t.Fatalf("FormatWithLimits() error = %v", err)
	}
	if int64(len(payload)) > codecLimits.MaxOutputBytes {
		t.Fatalf("canonical bytes = %d, bound = %d", len(payload), codecLimits.MaxOutputBytes)
	}
	escaped := []byte(strings.Repeat(scalar, low))
	if scalar != "a" {
		unit := fmt.Sprintf(`\u%04x`, []rune(scalar)[0])
		if bytes.Count(payload, []byte(unit)) != low {
			t.Fatal("admitted control scalar count changed during formatting")
		}
		escaped = []byte(strings.Repeat(unit, low))
	}
	if low == 0 || bytes.Count(payload, escaped) != 1 {
		t.Fatal("maximal control text was not escaped exactly")
	}
	parsed, err := ParseWithLimits(payload, codecLimits, limits)
	if err != nil || !projectionsEqual(model, parsed.Model) {
		t.Fatal("maximal admitted text did not round trip under paired limits")
	}
	over := testDraft()
	set(&over, "X"+strings.Repeat(scalar, high)+"Y")
	if _, err := requirementsourcemodel.NormalizeWithLimits(over, limits); requirementsourcemodel.ErrorCode(err) != limitCode {
		t.Fatalf("limit-plus-one model error = %v", err)
	}
}

func assertCoefficientRows(t *testing.T, expected []coefficientItem, actual []limitCoefficient) {
	t.Helper()
	converted := make([]coefficientItem, len(actual))
	for index, row := range actual {
		converted[index] = coefficientItem{ID: row.ID, Coefficient: row.Coefficient}
	}
	sort.Slice(converted, func(left, right int) bool { return converted[left].ID < converted[right].ID })
	if !reflect.DeepEqual(expected, converted) {
		t.Fatalf("coefficient rows = %#v, want %#v", converted, expected)
	}
}
