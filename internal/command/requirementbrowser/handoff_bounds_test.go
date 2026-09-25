package requirementbrowser

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestHandoffRequestByteBoundary(t *testing.T) {
	session := workspaceSessionForInvariant(t, "The system preserves semantic identity.")
	body := encodedHandoffBody(t, []any{handoffAnnotation(11, 20, "preserves", "Does this remain true?")})
	exact := append(body, bytes.Repeat([]byte(" "), maxHandoffRequestBytes-len(body))...)
	if _, err := buildHandoffPacket(httptest.NewRequest(http.MethodPost, "/api/v1/handoff", bytes.NewReader(exact)), session); err != nil {
		t.Fatalf("exact request byte bound was rejected: %v", err)
	}
	over := append(exact, ' ')
	if _, err := buildHandoffPacket(httptest.NewRequest(http.MethodPost, "/api/v1/handoff", bytes.NewReader(over)), session); err == nil || !strings.Contains(err.Error(), "handoff exceeds byte limit") {
		t.Fatalf("request above byte bound was not rejected: %v", err)
	}
}

func TestHandoffAnnotationCountBoundary(t *testing.T) {
	session := workspaceSessionForInvariant(t, "The system preserves semantic identity. "+strings.Repeat("x", maxHandoffAnnotations+1))
	anchor := session.Anchors["requirement:REQ-CONSUMER-001:invariant"]
	first := strings.Index(anchor.Text, strings.Repeat("x", 3))
	annotations := make([]any, 0, maxHandoffAnnotations+1)
	for index := 0; index <= maxHandoffAnnotations; index++ {
		annotations = append(annotations, handoffAnnotation(first+index, first+index+1, "x", "Does this remain true?"))
	}
	if _, err := buildHandoffPacket(handoffRequest(t, annotations[:maxHandoffAnnotations]), session); err != nil {
		t.Fatalf("exact annotation count bound was rejected: %v", err)
	}
	if _, err := buildHandoffPacket(handoffRequest(t, annotations), session); err == nil || !strings.Contains(err.Error(), "1 to 64 records") {
		t.Fatalf("annotation count above bound was not rejected: %v", err)
	}
}

func TestHandoffQuoteAndQuestionByteBoundaries(t *testing.T) {
	invariant := strings.Repeat("q", maxHandoffQuoteBytes+1)
	session := workspaceSessionForInvariant(t, invariant)
	anchorID := "requirement:REQ-CONSUMER-001:invariant"
	if _, err := admitAnnotation(handoffAnnotationRecord(anchorID, 0, maxHandoffQuoteBytes, invariant[:maxHandoffQuoteBytes], strings.Repeat("a", maxHandoffQuestionBytes)), session); err != nil {
		t.Fatalf("exact quote and question bounds were rejected: %v", err)
	}
	if _, err := admitAnnotation(handoffAnnotationRecord(anchorID, 0, maxHandoffQuoteBytes+1, invariant, "Why?"), session); err == nil || !strings.Contains(err.Error(), "quote is invalid") {
		t.Fatalf("quote above byte bound was not rejected: %v", err)
	}
	if _, err := admitAnnotation(handoffAnnotationRecord(anchorID, 0, 1, "q", strings.Repeat("a", maxHandoffQuestionBytes+1)), session); err == nil || !strings.Contains(err.Error(), "question exceeds byte limit") {
		t.Fatalf("question above byte bound was not rejected: %v", err)
	}
}

func TestHandoffQuestionUTF8ByteBoundaries(t *testing.T) {
	session := workspaceSessionForInvariant(t, "q")
	for _, item := range []struct{ name, unit string }{
		{"ASCII", "a"}, {"CJK", "\u754c"}, {"astral", "\U0001f9ed"}, {"combining", "e\u0301"},
	} {
		t.Run(item.name, func(t *testing.T) {
			question := strings.Repeat(item.unit, maxHandoffQuestionBytes/len(item.unit)) + strings.Repeat("a", maxHandoffQuestionBytes%len(item.unit))
			annotation, err := admitAnnotation(handoffAnnotation(0, 1, "q", question), session)
			if err != nil || annotation["question"] != question {
				t.Fatalf("exact byte limit did not retain the original question: %v", err)
			}
			if _, err := admitAnnotation(handoffAnnotation(0, 1, "q", question+"b"), session); err == nil || !strings.Contains(err.Error(), "question exceeds byte limit") {
				t.Fatalf("one byte over the question limit was not rejected: %v", err)
			}
		})
	}
}

func TestHandoffQuestionTrimSpaceByteBoundaries(t *testing.T) {
	session := workspaceSessionForInvariant(t, "q")
	for _, item := range []struct{ name, left, right, retainedLeft, retainedRight string }{
		{name: "leading NEL", left: "\u0085"},
		{name: "trailing NEL", right: "\u0085"},
		{name: "both-edge NEL", left: "\u0085", right: "\u0085"},
		{name: "mixed whitespace", left: " \t\u00a0\u0085\u2003", right: "\u2009\u0085\u202f\n "},
		{name: "BOM is not server whitespace", left: "\ufeff", right: "\ufeff", retainedLeft: "\ufeff", retainedRight: "\ufeff"},
		{name: "BOM hidden by NEL", left: "\u0085\ufeff", right: "\ufeff\u0085", retainedLeft: "\ufeff", retainedRight: "\ufeff"},
		{name: "whitespace inside BOM is retained", left: "\u0085\ufeff \u0085", right: "\u0085 \ufeff\u0085", retainedLeft: "\ufeff \u0085", retainedRight: "\u0085 \ufeff"},
	} {
		t.Run(item.name, func(t *testing.T) {
			coreBytes := maxHandoffQuestionBytes - len(item.retainedLeft) - len(item.retainedRight)
			core := strings.Repeat("\U0001f9ed", coreBytes/4) + strings.Repeat("a", coreBytes%4)
			exact := item.retainedLeft + core + item.retainedRight
			packet, err := buildHandoffPacket(handoffRequest(t, []any{handoffAnnotation(0, 1, "q", item.left+core+item.right)}), session)
			if err != nil {
				t.Fatalf("canonical question at byte limit was rejected: %v", err)
			}
			annotation := packet["annotations"].([]any)[0].(map[string]any)
			if packet["state"] != "submitted" || annotation["question"] != exact || len(exact) != maxHandoffQuestionBytes {
				t.Fatal("packet must retain the exact server-trimmed question at the byte limit")
			}
			if _, err := buildHandoffPacket(handoffRequest(t, []any{handoffAnnotation(0, 1, "q", item.left+core+"b"+item.right)}), session); err == nil || !strings.Contains(err.Error(), "question exceeds byte limit") {
				t.Fatalf("canonical question one byte over limit was not rejected: %v", err)
			}
		})
	}
}

func TestHandoffQuestionTrimSpaceNonEmptyControls(t *testing.T) {
	session := workspaceSessionForInvariant(t, "q")
	for _, item := range []struct{ name, question, want string }{
		{"empty whitespace", "\u0085 \t\u0085", ""},
		{"BOM only", "\ufeff", "\ufeff"},
		{"NEL-hidden BOM", "\u0085\ufeff\u0085", "\ufeff"},
		{"BOM outside NEL", "\ufeff\u0085\ufeff", "\ufeff\u0085\ufeff"},
		{"internal whitespace and normalization forms", "\u0085e\u0301 \u0085\ufeff \u00e9\u0085", "e\u0301 \u0085\ufeff \u00e9"},
	} {
		t.Run(item.name, func(t *testing.T) {
			annotation, err := admitAnnotation(handoffAnnotation(0, 1, "q", item.question), session)
			if item.want == "" {
				if err == nil || !strings.Contains(err.Error(), "must be non-empty text") {
					t.Fatalf("Go-whitespace-only question was not rejected as empty: %v", err)
				}
				return
			}
			if err != nil || annotation["question"] != item.want {
				t.Fatalf("server-only trimming changed question: %v", err)
			}
		})
	}
}

func TestHandoffDerivedContextByteBoundary(t *testing.T) {
	session := workspaceSessionForInvariant(t, strings.Repeat("c", maxHandoffContextBytes))
	if _, err := buildHandoffPacket(handoffRequest(t, []any{handoffAnnotation(0, 1, "c", "Why?")}), session); err == nil || !strings.Contains(err.Error(), "review context exceeds byte limit") {
		t.Fatalf("oversized derived context was not rejected: %v", err)
	}
}

func TestHandoffFinalPacketByteBoundaryIsReachable(t *testing.T) {
	const quoteBytes = 16204
	contextBytes := func(session workspaceSession) int {
		slice, err := requirementcontext.SliceSnapshot(session.Snapshot, map[string]any{
			"profile": "review", "maxNodes": json.Number("4096"), "maxRequirements": json.Number("16384"),
			"requirementIds": []any{"REQ-CONSUMER-001"},
		}, "browser.handoff.context")
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := stablejson.Marshal(slice)
		if err != nil {
			t.Fatal(err)
		}
		return len(encoded)
	}
	overhead := contextBytes(workspaceSessionForInvariant(t, "z")) - 1
	invariantBytes := maxHandoffContextBytes - overhead
	session := workspaceSessionForInvariant(t, strings.Repeat("z", invariantBytes))
	if size := contextBytes(session); size != maxHandoffContextBytes {
		t.Fatalf("final-packet fixture must reach the valid context boundary: got %d, want %d", size, maxHandoffContextBytes)
	}
	anchor := session.Anchors["requirement:REQ-CONSUMER-001:invariant"]
	annotations := make([]any, maxHandoffAnnotations)
	for index := range annotations {
		annotations[index] = handoffAnnotation(index, index+quoteBytes, anchor.Text[index:index+quoteBytes], "Why?")
	}
	if size := len(encodedHandoffBody(t, annotations)); size > maxHandoffRequestBytes {
		t.Fatalf("calibrated final-packet fixture exceeds request bound: %d", size)
	}
	if _, err := buildHandoffPacket(handoffRequest(t, annotations), session); err == nil || !strings.Contains(err.Error(), "packet exceeds byte limit") {
		t.Fatalf("composed payload above final packet bound was not rejected: %v", err)
	}
}

func workspaceSessionForInvariant(t *testing.T, invariant string) workspaceSession {
	t.Helper()
	session, _, err := buildWorkspace(workspaceFixtureWithInvariant(t, invariant))
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func handoffRequest(t *testing.T, annotations []any) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodPost, "/api/v1/handoff", bytes.NewReader(encodedHandoffBody(t, annotations)))
}

func encodedHandoffBody(t *testing.T, annotations []any) []byte {
	t.Helper()
	encoded, err := stablejson.Marshal(map[string]any{"annotations": annotations})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func handoffAnnotation(start, end int, quote, question string) map[string]any {
	return handoffAnnotationRecord("requirement:REQ-CONSUMER-001:invariant", start, end, quote, question)
}

func handoffAnnotationRecord(anchorID string, start, end int, quote, question string) map[string]any {
	return map[string]any{
		"anchorId":       anchorID,
		"endCodePoint":   json.Number(strconv.Itoa(end)),
		"exactQuote":     quote,
		"question":       question,
		"startCodePoint": json.Number(strconv.Itoa(start)),
	}
}
