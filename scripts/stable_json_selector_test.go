package main

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/testsupport/nodetestselector"
)

const stableJSONSelectorTimeout = 45 * time.Second

func TestStableJSONJavaScriptUnicodePredicates(t *testing.T) {
	runStableJSONJavaScriptSelectors(t, []string{
		"stable JSON Unicode corpus",
		"stable JSON Unicode table classifies every scalar and complement",
		"stableJSONStringify admits every valid UTF-16 surrogate pair in keys and values",
		"stableJSONStringify escapes unsafe scalars and preserves scalar key order",
		"stableJSONStringify rejects every unpaired surrogate code unit in keys and values",
	})
}

func TestStableJSONJavaScriptDiagnosticWholeValueRedaction(t *testing.T) {
	runStableJSONJavaScriptSelectors(t, []string{"diagnostic whole-value redaction"})
}

func runStableJSONJavaScriptSelectors(t *testing.T, names []string) {
	t.Helper()
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("locate node: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), stableJSONSelectorTimeout)
	defer cancel()
	if err := nodetestselector.RunSet(ctx, nodePath, ".", "stable-json.test.mjs", names); err != nil {
		t.Fatalf("run exact JavaScript selector set: %v", err)
	}
}
