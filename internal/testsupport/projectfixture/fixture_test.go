package projectfixture

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestProjectFixtureHasIndependentRecordsFilesAndCalls(t *testing.T) {
	first, second := New(t), New(t)
	if first.Root == second.Root || !bytes.Equal(jsonBytes(t, first.Project), jsonBytes(t, second.Project)) {
		t.Fatal("fresh fixture does not preserve equivalent independent project inputs")
	}
	want := jsonBytes(t, second.Project)
	first.Project["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)[0].(map[string]any)["invariant"] = "Mutated fixture input."
	for path, content := range first.Files {
		content[0] = '!'
		onDisk, err := os.ReadFile(filepath.Join(first.Root, filepath.FromSlash(path)))
		if err != nil || !bytes.Equal(onDisk, second.Files[path]) {
			t.Fatal("returned fixture bytes alias persisted input or another fixture")
		}
	}
	if !bytes.Equal(want, jsonBytes(t, second.Project)) || !bytes.Equal(want, jsonBytes(t, New(t).Project)) {
		t.Fatal("changing one fixture changes a sibling or later fixture")
	}
}
