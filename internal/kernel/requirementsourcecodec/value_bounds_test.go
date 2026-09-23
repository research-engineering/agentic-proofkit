package requirementsourcecodec

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestValuePreflightBoundsKeysAndNumbers(t *testing.T) {
	modelLimits := compactTestModelLimits()
	codecLimits := pairedCodecLimits(t, modelLimits)
	oversized := int(codecLimits.MaxRawBytes) + 1
	for _, test := range []struct {
		name  string
		value any
	}{
		{"keys", map[string]any{strings.Repeat("x", oversized) + "a": nil, strings.Repeat("x", oversized) + "b": nil}},
		{"number", map[string]any{"schemaVersion": json.Number(strings.Repeat("0", oversized))}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := AssessValueWithLimits(test.value, codecLimits, modelLimits)
			if ErrorCode(err) != "raw_byte_limit_exceeded" {
				t.Fatalf("content admission ran before byte preflight: %v", err)
			}
		})
	}
	encoder := valueEncoder{writer: canonicalWriter{maxBytes: 8}, maxDepth: 8}
	encoder.encode(map[string]any{"aaaaa": make(chan int), "aaaab": make(chan int)},
		&shape{kind: shapeObject, dynamic: scalar(shapeString), maxItems: 2}, "", 1)
	if ErrorCode(encoder.writer.err) != "raw_byte_limit_exceeded" || encoder.writer.buffer.Len() != 0 {
		t.Fatalf("aggregate keys were materialized before preflight: %v, bytes = %d", encoder.writer.err, encoder.writer.buffer.Len())
	}
}

func TestValueEncodingBoundsBeforeMaterialization(t *testing.T) {
	modelLimits := requirementsourcemodel.DefaultLimits()
	root := decodedTestValue(t, mustPayload(t))
	encode := func(limit int64) *valueEncoder {
		encoder := &valueEncoder{writer: canonicalWriter{maxBytes: limit}, maxDepth: DefaultLimits().MaxNesting}
		encoder.encode(root, documentShape(modelLimits), "", 1)
		return encoder
	}
	baseline := encode(DefaultLimits().MaxRawBytes)
	if baseline.writer.err != nil {
		t.Fatal(baseline.writer.err)
	}
	size := int64(baseline.writer.buffer.Len())
	for _, limit := range []int64{size - 1, size, size + 1} {
		encoder := encode(limit)
		if int64(encoder.writer.buffer.Len()) > limit {
			t.Fatal("encoding materialized more than its byte budget")
		}
		if limit < size {
			if ErrorCode(encoder.writer.err) != "raw_byte_limit_exceeded" {
				t.Fatalf("overflow error = %v", encoder.writer.err)
			}
		} else if encoder.writer.err != nil || encoder.writer.buffer.String() != baseline.writer.buffer.String() {
			t.Fatalf("accepted boundary %d drifted: %v", limit, encoder.writer.err)
		}
	}
	encoder := &valueEncoder{writer: canonicalWriter{maxBytes: 2}, maxDepth: 8}
	encoder.encode("\n", scalar(shapeString), "", 1)
	if ErrorCode(encoder.writer.err) != "raw_byte_limit_exceeded" || encoder.writer.buffer.Len() > 2 {
		t.Fatalf("escaped string overflow = %v", encoder.writer.err)
	}
}

func TestValueCollectionBudgetDominatesElementSemantics(t *testing.T) {
	shape := &shape{kind: shapeArray, maxItems: 1, element: scalar(shapeString)}
	encoder := valueEncoder{writer: canonicalWriter{maxBytes: 4096}, maxDepth: 8}
	encoder.encode([]any{"valid", make(chan int)}, shape, "/items", 1)
	if ErrorCode(encoder.writer.err) != "collection_limit_exceeded" || encoder.writer.buffer.Len() != 0 {
		t.Fatalf("out-of-budget element was visited: %v", encoder.writer.err)
	}
	encoder = valueEncoder{writer: canonicalWriter{maxBytes: 4096}, maxDepth: 1}
	encoder.encode([]any{"value"}, shape, "/items", 1)
	if ErrorCode(encoder.writer.err) != "nesting_limit_exceeded" {
		t.Fatalf("depth bound = %v", encoder.writer.err)
	}
}

func TestAssessValueEnforcesPairedPublicBounds(t *testing.T) {
	modelLimits := compactTestModelLimits()
	codecLimits := pairedCodecLimits(t, modelLimits)
	root := decodedTestValue(t, mustPayload(t)).(map[string]any)
	root["sourceId"] = strings.Repeat("x", int(codecLimits.MaxRawBytes)+1)
	if _, err := AssessValueWithLimits(root, codecLimits, modelLimits); ErrorCode(err) != "raw_byte_limit_exceeded" {
		t.Fatalf("public bounded value admission = %v", err)
	}
	codecLimits.MaxRawBytes = 0
	if _, err := AssessValueWithLimits(nil, codecLimits, modelLimits); err == nil {
		t.Fatal("invalid paired limits were accepted")
	}
}
