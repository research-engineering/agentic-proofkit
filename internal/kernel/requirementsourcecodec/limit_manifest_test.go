package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
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
	limits := compactTestModelLimits()
	low := 0
	high := limits.MaxTotalTextBytes/2 + 1
	for low+1 < high {
		middle := low + (high-low)/2
		draft := testDraft()
		draft.NonClaimDefinitions[0].Statement = "X" + strings.Repeat("\u0085", middle) + "Y"
		if _, err := requirementsourcemodel.NormalizeWithLimits(draft, limits); err == nil {
			low = middle
		} else {
			high = middle
		}
	}
	draft := testDraft()
	draft.NonClaimDefinitions[0].Statement = "X" + strings.Repeat("\u0085", low) + "Y"
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
	if !bytes.Contains(payload, []byte(`\u0085`)) {
		t.Fatal("worst-case admitted control scalar was not escaped")
	}
	over := testDraft()
	over.NonClaimDefinitions[0].Statement = "X" + strings.Repeat("\u0085", high) + "Y"
	if _, err := requirementsourcemodel.NormalizeWithLimits(over, limits); requirementsourcemodel.ErrorCode(err) != "text_budget_exceeded" {
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
