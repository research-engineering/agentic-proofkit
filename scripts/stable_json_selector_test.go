package main

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/nodetestselector"
)

func TestStableJSONJavaScriptUnicodePolicy(t *testing.T) {
	runStableJSONJavaScriptSelector(t, "stableJSONStringify escapes unsafe scalars and preserves scalar key order")
}

func TestStableJSONJavaScriptUnicodeCorpus(t *testing.T) {
	runStableJSONJavaScriptSelector(t, "stable JSON Unicode corpus")
}

func TestStableJSONJavaScriptExhaustiveUnicodeTable(t *testing.T) {
	runStableJSONJavaScriptSelector(t, "stable JSON Unicode table classifies every scalar and complement")
}

func TestStableJSONJavaScriptRejectsEverySurrogate(t *testing.T) {
	runStableJSONJavaScriptSelector(t, "stableJSONStringify rejects every unpaired surrogate code unit in keys and values")
}

func TestStableJSONJavaScriptAdmitsEverySurrogatePair(t *testing.T) {
	runStableJSONJavaScriptSelector(t, "stableJSONStringify admits every valid UTF-16 surrogate pair in keys and values")
}

func TestStableJSONJavaScriptDiagnosticWholeValueRedaction(t *testing.T) {
	runStableJSONJavaScriptSelector(t, "diagnostic whole-value redaction")
}

func runStableJSONJavaScriptSelector(t *testing.T, name string) {
	t.Helper()
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("locate node: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if err := nodetestselector.Run(ctx, nodePath, ".", "stable-json.test.mjs", name); err != nil {
		t.Fatalf("run exact JavaScript selector: %v", err)
	}
}
