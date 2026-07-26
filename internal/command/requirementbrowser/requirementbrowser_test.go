package requirementbrowser

import (
	"strings"
	"testing"
)

func TestInvalidViewListsEverySupportedView(t *testing.T) {
	_, _, err := BuildPlan(map[string]any{}, Options{Host: "127.0.0.1", PortSet: true, View: "invalid"})
	if err == nil {
		t.Fatal("BuildPlan accepted an invalid view")
	}
	message := err.Error()
	for _, view := range []string{"source", "proof", "coverage", "spec-tree", "workspace"} {
		if strings.Count(message, view) != 1 {
			t.Fatalf("invalid-view diagnostic count for %q=%d, want 1: %s", view, strings.Count(message, view), message)
		}
	}
}
