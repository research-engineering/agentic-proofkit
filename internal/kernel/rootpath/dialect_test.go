package rootpath

import (
	"errors"
	"os"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathidentity"
)

func TestExactEntryUsesOneAdmittedDialect(t *testing.T) {
	for _, row := range []struct {
		present, requested string
		currentAlias       bool
	}{
		{"s\u015b", "\u00df\u0301", true},
		{"\u03b1\u03b9\u030a", "\u1fb3\u030a", false},
	} {
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		file, err := root.Create(row.present)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		// One stored entry only: this tests the string-policy gate, not native
		// alias resolution or coexistence of two names on this filesystem.
		for _, dialect := range []pathidentity.Dialect{pathidentity.Legacy, pathidentity.CanonicalCaseless} {
			alias := row.currentAlias
			if dialect == pathidentity.Legacy {
				alias = !alias
			}
			exists, err := ExactEntryExistsIn(root, ".", row.requested, dialect)
			if exists || errors.Is(err, ErrAmbiguousRoute) != alias || !alias && err != nil {
				t.Fatalf("dialect %d: %t %v", dialect, exists, err)
			}
			exists, err = ExactEntryExistsIn(root, ".", row.present, dialect)
			if err != nil || !exists {
				t.Fatalf("exact spelling lost: %t %v", exists, err)
			}
		}
		if _, err := ExactEntryExistsIn(root, ".", row.present, 0); err == nil {
			t.Fatal("zero dialect admitted")
		}
	}
}
