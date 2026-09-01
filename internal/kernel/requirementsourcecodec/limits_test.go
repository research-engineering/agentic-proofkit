package requirementsourcecodec

import (
	"bytes"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestRawByteBoundaryIsExactAndDominatesUTF8(t *testing.T) {
	modelLimits := compactTestModelLimits()
	codecLimits := pairedCodecLimits(t, modelLimits)
	model, err := requirementsourcemodel.NormalizeWithLimits(testDraft(), modelLimits)
	if err != nil {
		t.Fatalf("NormalizeWithLimits() error = %v", err)
	}
	payload, err := FormatWithLimits(model, codecLimits, modelLimits)
	if err != nil {
		t.Fatalf("FormatWithLimits() error = %v", err)
	}
	remaining := int(codecLimits.MaxRawBytes) - len(payload)
	if remaining < 0 {
		t.Fatal("canonical payload exceeds configured raw limit")
	}
	atLimit := append(append([]byte(nil), payload...), bytes.Repeat([]byte{' '}, remaining)...)
	if _, err := ParseWithLimits(atLimit, codecLimits, modelLimits); err != nil {
		t.Fatalf("ParseWithLimits(exact limit) error = %v", err)
	}
	overLimit := append([]byte{0xff}, atLimit...)
	_, err = ParseWithLimits(overLimit, codecLimits, modelLimits)
	assertDiagnostic(t, err, "raw_byte_limit_exceeded", "")
	if err.(*Error).Diagnostic().CoordinateState != "byte_only" {
		t.Fatal("raw overflow must not inspect invalid UTF-8")
	}
}

func TestTokenAndNestingLimitsPrecedeShapeAdmission(t *testing.T) {
	modelLimits := compactTestModelLimits()
	codecLimits := pairedCodecLimits(t, modelLimits)
	items := codecLimits.MaxTokens + 1
	tokenOverflow := []byte("[" + strings.Repeat("0,", items) + "0]")
	if int64(len(tokenOverflow)) > codecLimits.MaxRawBytes {
		t.Fatal("token falsifier unexpectedly exceeds raw-byte bound")
	}
	_, err := ParseWithLimits(tokenOverflow, codecLimits, modelLimits)
	if ErrorCode(err) != "token_limit_exceeded" {
		t.Fatalf("token overflow error = %v", err)
	}

	codecLimits.MaxNesting = minimumJSONNesting
	nested := []byte(strings.Repeat("[", minimumJSONNesting+1) + "0" + strings.Repeat("]", minimumJSONNesting+1))
	_, err = ParseWithLimits(nested, codecLimits, modelLimits)
	if ErrorCode(err) != "nesting_limit_exceeded" {
		t.Fatalf("nested input error = %v", err)
	}
}

func TestLexicalTokenLimitDominatesNestingWhenBothFail(t *testing.T) {
	modelLimits := compactTestModelLimits()
	codecLimits := pairedCodecLimits(t, modelLimits)
	payload := []byte(strings.Repeat("[", codecLimits.MaxNesting+1) + strings.Repeat("0,", codecLimits.MaxTokens) + "0" + strings.Repeat("]", codecLimits.MaxNesting+1))
	if int64(len(payload)) > codecLimits.MaxRawBytes {
		t.Fatal("combined precedence falsifier unexpectedly exceeds the raw-byte bound")
	}
	_, err := ParseWithLimits(payload, codecLimits, modelLimits)
	if ErrorCode(err) != "token_limit_exceeded" {
		t.Fatalf("combined token/nesting error = %v", err)
	}
}

func TestRepresentationCollectionLimitPrecedesModelSemantics(t *testing.T) {
	modelLimits := compactTestModelLimits()
	codecLimits := pairedCodecLimits(t, modelLimits)
	payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		definitions := root["nonClaimDefinitions"].([]any)
		root["nonClaimDefinitions"] = append(definitions, definitions[0])
	})
	_, err := ParseWithLimits(payload, codecLimits, modelLimits)
	assertDiagnostic(t, err, "collection_limit_exceeded", "/nonClaimDefinitions")
}

func TestDynamicMapCollectionLimitPrecedesParameterSemantics(t *testing.T) {
	modelLimits := compactTestModelLimits()
	codecLimits := pairedCodecLimits(t, modelLimits)
	payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		scenarios := root["scenarios"].([]any)
		examples := scenarios[0].(map[string]any)["examples"].([]any)
		values := examples[0].(map[string]any)["values"].(map[string]any)
		for index := 0; index <= modelLimits.MaxCollectionItems; index++ {
			values["key"+strings.Repeat("x", index+1)] = "value"
		}
	})
	_, err := ParseWithLimits(payload, codecLimits, modelLimits)
	assertDiagnostic(t, err, "collection_limit_exceeded", "/scenarios/0/examples/0/values")
}

func TestModelResourcePreflightPrecedesSemanticValidation(t *testing.T) {
	modelLimits := compactTestModelLimits()
	codecLimits := pairedCodecLimits(t, modelLimits)
	payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		root["sourceId"] = "invalid source id"
		definitions := root["nonClaimDefinitions"].([]any)
		definitions[0].(map[string]any)["statement"] = strings.Repeat("x", modelLimits.MaxTotalTextBytes+1)
	})
	_, err := ParseWithLimits(payload, codecLimits, modelLimits)
	if ErrorCode(err) != "text_budget_exceeded" {
		t.Fatalf("resource/semantic precedence error = %v", err)
	}
}

func TestCodecLimitsCannotUnderCoverModel(t *testing.T) {
	modelLimits := compactTestModelLimits()
	codecLimits := pairedCodecLimits(t, modelLimits)
	codecLimits.MaxOutputBytes--
	_, err := ParseWithLimits(mustPayload(t), codecLimits, modelLimits)
	if err == nil || ErrorCode(err) != "" {
		t.Fatalf("invalid configuration error = %v", err)
	}

	codecLimits = pairedCodecLimits(t, modelLimits)
	codecLimits.MaxNesting = minimumJSONNesting - 1
	_, err = ParseWithLimits(mustPayload(t), codecLimits, modelLimits)
	if err == nil || ErrorCode(err) != "" {
		t.Fatalf("under-nested configuration error = %v", err)
	}

	modelLimits.MaxExpandedItems = 0
	_, err = ParseWithLimits(mustPayload(t), pairedCodecLimits(t, compactTestModelLimits()), modelLimits)
	if err == nil || ErrorCode(err) != "" || err.Error() != "invalid model limits" {
		t.Fatalf("invalid model configuration error = %v", err)
	}
}

func compactTestModelLimits() requirementsourcemodel.Limits {
	limits := requirementsourcemodel.DefaultLimits()
	limits.MaxDefinitions = 4
	limits.MaxDerivations = 1
	limits.MaxExamples = 2
	limits.MaxExamplesPerScenario = 2
	limits.MaxCollectionItems = 128
	limits.MaxGroups = 3
	limits.MaxMembers = 4
	limits.MaxMembersPerGroup = 2
	limits.MaxProfiles = 1
	limits.MaxScenarios = 1
	limits.MaxTerms = 1
	limits.MaxTotalTextBytes = 16 << 10
	return limits
}

func pairedCodecLimits(t testing.TB, modelLimits requirementsourcemodel.Limits) Limits {
	t.Helper()
	maxBytes, err := MaxCanonicalBytes(modelLimits)
	if err != nil {
		t.Fatalf("MaxCanonicalBytes() error = %v", err)
	}
	maxTokens, err := MaxLexicalTokens(modelLimits)
	if err != nil {
		t.Fatalf("MaxLexicalTokens() error = %v", err)
	}
	return Limits{MaxRawBytes: maxBytes, MaxTokens: maxTokens, MaxNesting: defaultMaxNesting, MaxOutputBytes: maxBytes}
}
