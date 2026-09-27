package repositorytransaction

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

type namedControlEntry string

func (name namedControlEntry) Name() string               { return string(name) }
func (name namedControlEntry) IsDir() bool                { return false }
func (name namedControlEntry) Type() fs.FileMode          { return 0 }
func (name namedControlEntry) Info() (fs.FileInfo, error) { return nil, os.ErrInvalid }

func TestCanonicalControlObservationVersionNamesAndOrder(t *testing.T) {
	entries := []fs.DirEntry{namedControlEntry("f"), namedControlEntry("\u00e9")}
	if err := sortInspectionEntries(entries); err != nil || entries[0].Name() != "\u00e9" {
		t.Fatalf("current key order: %v", err)
	}
	if err := sortInspectionEntries([]fs.DirEntry{namedControlEntry("s\u015b"), namedControlEntry("\u00df\u0301")}); err == nil {
		t.Fatal("merged observation class admitted")
	}
	if err := sortInspectionEntries([]fs.DirEntry{namedControlEntry("\u1fb3\u030a"), namedControlEntry("\u03b1\u03b9\u030a")}); err != nil {
		t.Fatal("split observation class rejected")
	}
	wantEmpty, err := digest.StableJSONSHA256Ref(map[string]any{"controlObservationKind": "proofkit.repository-control-observation", "entries": []any{}, "schemaVersion": json.Number("2")})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := emptyControlObservationID(); err != nil || got != wantEmpty {
		t.Fatal("empty observation is not v2")
	}
	root, _, err := openRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := ensureDirectory(root, ControlDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeOwnedFile(root, ControlDirectory+"/caf\u00e9", []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	observation, err := observeControlNamespace(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	want, err := digest.StableJSONSHA256Ref(map[string]any{
		"controlObservationKind": "proofkit.repository-control-observation", "schemaVersion": json.Number("2"),
		"entries": []any{map[string]any{"kind": "regular", "nameId": digest.SHA256TextRef("cafe\u0301"), "contentId": digest.SHA256TextRef("data"), "mode": json.Number("384"), "size": json.Number("4")}},
	})
	if err != nil || observation.Digest != want {
		t.Fatal("observation identity is not the exact v2 current-key payload")
	}
}
