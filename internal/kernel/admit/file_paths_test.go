package admit

import "testing"

func TestRepoFilePathsOverlapUsesExactComponents(t *testing.T) {
	for _, row := range []struct {
		left, right string
		conflict    bool
	}{
		{"inputs/a", "inputs/a", true},
		{"inputs/a", "inputs/a/b.json", true},
		{"inputs/a", "inputs/ab.json", false},
		{"inputs/a", "inputs/a-b.json", false},
		{"inputs/A", "inputs/a", false},
		{"inputs/a ", "inputs/a /b.json", true},
		{"inputs/a ", "inputs/a/b.json", false},
		{"inputs/*", "inputs/file", false},
	} {
		if RepoFilePathsOverlap(row.left, row.right) != row.conflict || RepoFilePathsOverlap(row.right, row.left) != row.conflict {
			t.Fatalf("component conflict differs for %q and %q", row.left, row.right)
		}
	}
}
