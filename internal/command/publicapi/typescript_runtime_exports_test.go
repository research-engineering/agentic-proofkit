package publicapi

import (
	"strings"
	"testing"
)

func TestRuntimeExportInventoryDoesNotAmplifyNestedWhitespace(t *testing.T) {
	const depth = 2000
	source := "export const A = " + strings.Repeat("[\n", depth) + "0" + strings.Repeat("\n]", depth) + ";"
	result := buildRuntimeExportInventory(source, ".ts")
	if len(result.Errors) != 0 || len(result.OutputFiles) != 1 {
		t.Fatalf("buildRuntimeExportInventory() errors=%v outputs=%d", result.Errors, len(result.OutputFiles))
	}
	if got := len(result.OutputFiles[0].Contents); got > 2*len(source) {
		t.Fatalf("generated JS length=%d exceeds twice source length=%d", got, len(source))
	}
	names, err := collectRuntimeExports(source, ".ts")
	if err != nil || len(names) != 1 || names[0] != "A" {
		t.Fatalf("collectRuntimeExports() names=%v error=%v", names, err)
	}
}
