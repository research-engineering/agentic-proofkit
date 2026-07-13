package requirementbrowser

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

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

func TestHandoffDerivedContextByteBoundary(t *testing.T) {
	session := workspaceSessionForInvariant(t, strings.Repeat("c", maxHandoffContextBytes))
	if _, err := buildHandoffPacket(handoffRequest(t, []any{handoffAnnotation(0, 1, "c", "Why?")}), session); err == nil || !strings.Contains(err.Error(), "review context exceeds byte limit") {
		t.Fatalf("oversized derived context was not rejected: %v", err)
	}
}

func TestHandoffFinalPacketByteBoundaryIsReachable(t *testing.T) {
	const invariantBytes = maxHandoffContextBytes - 2532
	const quoteBytes = 16204
	session := workspaceSessionForInvariant(t, strings.Repeat("z", invariantBytes))
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
