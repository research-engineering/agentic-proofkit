package repositorytransaction

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"testing"
)

var legacyPositiveCommand = flag.Bool("proofkit-require-legacy-unicode-positive", false, "require all 28 qualified legacy Unicode positive cases")

type caselessCoexistenceError struct {
	requested, existing string
	directory           bool
}

func (err *caselessCoexistenceError) Error() string {
	return "legacy Unicode fixture coexistence precondition is not met"
}

type caselessFixtureEntry struct {
	info    fs.FileInfo
	content []byte
}

// This inventory belongs only to the owned transaction fixture. It does not
// discover a filesystem's equivalence relation or use the key under test.
type caselessFixture struct {
	root    string
	entries map[string]caselessFixtureEntry
}

func newCaselessFixture(root string) *caselessFixture {
	return &caselessFixture{root: root, entries: map[string]caselessFixtureEntry{}}
}

func (fixture *caselessFixture) verify(relative string) error {
	expected, ok := fixture.entries[relative]
	if !ok {
		return fmt.Errorf("fixture entry is not owned: %q", relative)
	}
	entries, err := os.ReadDir(filepath.Join(fixture.root, filepath.FromSlash(path.Dir(relative))))
	if err != nil {
		return err
	}
	exact := false
	for _, entry := range entries {
		exact = exact || entry.Name() == path.Base(relative)
	}
	if !exact {
		return fmt.Errorf("fixture exact spelling changed: %q", relative)
	}
	info, err := os.Lstat(filepath.Join(fixture.root, filepath.FromSlash(relative)))
	if err != nil {
		return err
	}
	if !os.SameFile(info, expected.info) || info.Mode() != expected.info.Mode() {
		return fmt.Errorf("fixture identity or mode changed: %q", relative)
	}
	if info.Mode().IsRegular() {
		content, err := os.ReadFile(filepath.Join(fixture.root, filepath.FromSlash(relative)))
		if err != nil {
			return err
		}
		if !bytes.Equal(content, expected.content) {
			return fmt.Errorf("fixture bytes changed: %q", relative)
		}
	}
	return nil
}

func (fixture *caselessFixture) verifyAll() error {
	for relative := range fixture.entries {
		if err := fixture.verify(relative); err != nil {
			return err
		}
	}
	return nil
}

func (fixture *caselessFixture) capture(relative string, content []byte, mode fs.FileMode, directory bool) error {
	info, err := os.Lstat(filepath.Join(fixture.root, filepath.FromSlash(relative)))
	if err != nil {
		return err
	}
	if info.Mode().Perm() != mode || info.IsDir() != directory || !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("fixture type or mode is invalid: %q", relative)
	}
	for other, expected := range fixture.entries {
		if other != relative && os.SameFile(info, expected.info) {
			return fmt.Errorf("fixture identities are not distinct: %q", relative)
		}
	}
	fixture.entries[relative] = caselessFixtureEntry{info: info, content: bytes.Clone(content)}
	return fixture.verify(relative)
}

func (fixture *caselessFixture) coexistence(relative string, cause error) error {
	if !errors.Is(cause, fs.ErrExist) {
		return cause
	}
	existing := ""
	switch relative {
	case "docs/\u00df\u0301.txt":
		existing = "docs/s\u015b.txt"
	case "\u1fb3\u030a":
		existing = "\u03b1\u030a\u03b9"
	default:
		return cause
	}
	prior, owned := fixture.entries[existing]
	if _, duplicate := fixture.entries[relative]; !owned || duplicate {
		return cause
	}
	if err := fixture.verifyAll(); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(fixture.root, filepath.FromSlash(path.Dir(relative))))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == path.Base(relative) {
			return cause
		}
	}
	observed, err := os.Lstat(filepath.Join(fixture.root, filepath.FromSlash(relative)))
	if err != nil {
		return err
	}
	if !os.SameFile(observed, prior.info) {
		return cause
	}
	return &caselessCoexistenceError{requested: relative, existing: existing, directory: prior.info.IsDir()}
}

func (fixture *caselessFixture) parents(relative string) error {
	parent := path.Dir(relative)
	if parent == "." {
		return nil
	}
	if _, owned := fixture.entries[parent]; owned {
		return fixture.verify(parent)
	}
	return fixture.mkdir(parent, 0755)
}

func (fixture *caselessFixture) mkdir(relative string, mode fs.FileMode) error {
	if err := fixture.parents(relative); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(fixture.root, filepath.FromSlash(relative)), mode); err != nil {
		return fixture.coexistence(relative, err)
	}
	if err := os.Chmod(filepath.Join(fixture.root, filepath.FromSlash(relative)), mode); err != nil {
		return err
	}
	return fixture.capture(relative, nil, mode, true)
}

func (fixture *caselessFixture) create(relative string, content []byte, mode fs.FileMode) error {
	if err := fixture.parents(relative); err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(fixture.root, filepath.FromSlash(relative)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fixture.coexistence(relative, err)
	}
	_, writeErr := file.Write(content)
	modeErr := file.Chmod(mode)
	if err := errors.Join(writeErr, modeErr, file.Close()); err != nil {
		return err
	}
	return fixture.capture(relative, content, mode, false)
}

func (fixture *caselessFixture) replace(relative string, content []byte, mode fs.FileMode) error {
	if _, exists := fixture.entries[relative]; !exists {
		return fixture.create(relative, content, mode)
	}
	if err := fixture.verify(relative); err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(fixture.root, filepath.FromSlash(relative)), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(info, fixture.entries[relative].info) {
		file.Close()
		return fmt.Errorf("fixture changed before prefix write")
	}
	if err := file.Truncate(0); err != nil {
		file.Close()
		return err
	}
	_, writeErr := file.Write(content)
	modeErr := file.Chmod(mode)
	if err := errors.Join(writeErr, modeErr, file.Close()); err != nil {
		return err
	}
	return fixture.capture(relative, content, mode, false)
}

func (fixture *caselessFixture) remove(relative string) error {
	if err := fixture.verify(relative); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(fixture.root, filepath.FromSlash(relative))); err != nil {
		return err
	}
	delete(fixture.entries, relative)
	return fixture.absent(relative)
}

func (fixture *caselessFixture) absent(relative string) error {
	_, err := os.Lstat(filepath.Join(fixture.root, filepath.FromSlash(relative)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fixture.coexistence(relative, fs.ErrExist)
}

func (fixture *caselessFixture) vector(plan Plan, prefix int, preparing bool) error {
	if err := fixture.verifyAll(); err != nil {
		return err
	}
	for _, directory := range plan.CreatedDirectories {
		if preparing {
			if err := fixture.absent(directory); err != nil {
				return err
			}
		} else if err := fixture.verify(directory); err != nil {
			return err
		}
	}
	for index, operation := range plan.Operations {
		expected, after := operation.Before, false
		if index < prefix {
			expected, after = operation.After, true
		}
		if !expected.Exists {
			if err := fixture.absent(operation.Path); err != nil {
				return err
			}
			continue
		}
		entry, ok := fixture.entries[operation.Path]
		content := []byte(caselessPayload(operation, after))
		if !ok || entry.info.Mode().Perm() != expected.Mode || !bytes.Equal(entry.content, content) || !contentMatches(content, expected) {
			return fmt.Errorf("fixture vector does not match frozen snapshot")
		}
	}
	return nil
}

type caselessCaseEvidence struct {
	id       string
	positive bool
}

func expectedLegacyPositiveIDs() []string {
	return []string{
		"v1/preparing-temp/rollback/0", "v1/preparing/rollback/0", "v1/committed/resume/3", "v1/rolled-back/rollback/0", "v1/terminal-only/resume/3",
		"v1/ready/resume/0", "v1/ready/rollback/0", "v1/ready/resume/1", "v1/ready/rollback/1", "v1/ready/resume/2", "v1/ready/rollback/2", "v1/ready/resume/3", "v1/ready/rollback/3",
		"v2/preparing-temp/rollback/0", "v2/preparing/rollback/0", "v2/committed/resume/4", "v2/rolled-back/rollback/0", "v2/terminal-only/resume/4",
		"v2/ready/resume/0", "v2/ready/rollback/0", "v2/ready/resume/1", "v2/ready/rollback/1", "v2/ready/resume/2", "v2/ready/rollback/2", "v2/ready/resume/3", "v2/ready/rollback/3", "v2/ready/resume/4", "v2/ready/rollback/4",
	}
}

func validateLegacyPositiveEvidence(required bool, setupErr error, observed []caselessCaseEvidence) error {
	var coexistence *caselessCoexistenceError
	if setupErr != nil && !errors.As(setupErr, &coexistence) {
		return fmt.Errorf("unknown fixture preparation failure: %w", setupErr)
	}
	if required && setupErr != nil {
		return fmt.Errorf("required Unicode positive corpus is not qualified: %w", setupErr)
	}
	want := expectedLegacyPositiveIDs()
	positive := setupErr == nil
	if !positive {
		want = []string{"non-representable-state-refusal/v1", "non-representable-state-refusal/v2"}
	}
	if len(observed) != len(want) {
		return fmt.Errorf("legacy witness evidence set is incomplete")
	}
	remaining := map[string]bool{}
	for _, id := range want {
		remaining[id] = true
	}
	for _, item := range observed {
		if !remaining[item.id] || item.positive != positive {
			return fmt.Errorf("legacy witness evidence identity/class is invalid")
		}
		delete(remaining, item.id)
	}
	return nil
}

func TestCanonicalFixtureModeAndEvidencePredicates(t *testing.T) {
	positive := []caselessCaseEvidence{}
	for _, id := range expectedLegacyPositiveIDs() {
		positive = append(positive, caselessCaseEvidence{id, true})
	}
	coexistence := &caselessCoexistenceError{}
	negative := []caselessCaseEvidence{{"non-representable-state-refusal/v1", false}, {"non-representable-state-refusal/v2", false}}
	for _, required := range []bool{false, true} {
		if err := validateLegacyPositiveEvidence(required, nil, positive); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateLegacyPositiveEvidence(false, coexistence, negative); err != nil {
		t.Fatal(err)
	}
	mutants := []struct {
		required bool
		err      error
		evidence []caselessCaseEvidence
	}{
		{true, coexistence, negative}, {true, nil, nil}, {false, nil, nil}, {false, coexistence, nil},
		{true, nil, positive[:27]}, {true, nil, append(append([]caselessCaseEvidence{}, positive...), positive[0])},
		{false, fs.ErrPermission, negative}, {false, fs.ErrExist, negative}, {true, coexistence, positive},
		{false, coexistence, positive}, {true, nil, negative},
	}
	duplicate := append([]caselessCaseEvidence{}, positive...)
	duplicate[27] = duplicate[0]
	wrong := append([]caselessCaseEvidence{}, positive...)
	wrong[0].id = "wrong"
	misclassified := append([]caselessCaseEvidence{}, positive...)
	misclassified[0].positive = false
	for _, evidence := range [][]caselessCaseEvidence{duplicate, wrong, misclassified} {
		mutants = append(mutants, struct {
			required bool
			err      error
			evidence []caselessCaseEvidence
		}{true, nil, evidence})
	}
	for index, mutant := range mutants {
		if err := validateLegacyPositiveEvidence(mutant.required, mutant.err, mutant.evidence); err == nil {
			t.Fatalf("evidence mutant %d admitted", index)
		}
	}
}

func TestCanonicalFixtureExclusivePreparationAndVector(t *testing.T) {
	fixture := newCaselessFixture(t.TempDir())
	if err := fixture.create("owned", []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	before := snapshotTestTree(t, fixture.root)
	if err := fixture.create("owned", []byte("overwritten"), 0644); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("duplicate creation: %v", err)
	}
	if !reflect.DeepEqual(before, snapshotTestTree(t, fixture.root)) {
		t.Fatal("exclusive creation changed existing bytes/mode")
	}
	if err := fixture.coexistence("unknown", fs.ErrExist); !errors.Is(err, fs.ErrExist) {
		t.Fatal("unknown collision disguised as coexistence")
	}
	if err := fixture.coexistence("docs/\u00df\u0301.txt", fs.ErrPermission); !errors.Is(err, fs.ErrPermission) {
		t.Fatal("operational error disguised as coexistence")
	}
	if err := os.WriteFile(filepath.Join(fixture.root, "owned"), []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.verifyAll(); err == nil {
		t.Fatal("independent readback missed changed bytes")
	}
	if err := fixture.replace("owned", []byte("after"), 0644); err == nil {
		t.Fatal("prefix write ignored foreign bytes")
	}
}

func TestCanonicalFixtureRejectsASCIISubstitution(t *testing.T) {
	original := loadCaselessPredecessors(t)["1"]
	_, plan := rebindCaselessJournal(t, original, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	item := preparedCaselessCase{plan: plan, scenario: caselessScenario{version: "1"}}
	if err := qualifyCaselessOriginals(t, []preparedCaselessCase{item}); err != nil {
		t.Fatal(err)
	}
	_, item.plan = rebindCaselessJournal(t, asciiPredecessor(original), plan.RootID)
	if err := qualifyCaselessOriginals(t, []preparedCaselessCase{item}); err == nil {
		t.Fatal("ASCII lifecycle was promoted to Unicode positive evidence")
	}
}

func TestCanonicalFixtureVectorRejectsIndependentMutants(t *testing.T) {
	for _, mutation := range []string{"mode", "identity", "existence", "byte-count", "digest"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := newCaselessFixture(t.TempDir())
			if err := fixture.create("docs/a.txt", []byte("old-a"), 0600); err != nil {
				t.Fatal(err)
			}
			plan := Plan{Operations: []Operation{{Path: "docs/a.txt", Before: snapshotForContent([]byte("old-a"), 0600)}}}
			if err := fixture.vector(plan, 0, true); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(fixture.root, "docs/a.txt")
			switch mutation {
			case "mode":
				if err := os.Chmod(name, 0644); err != nil {
					t.Fatal(err)
				}
			case "identity":
				if err := fixture.create("replacement", []byte("old-a"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(filepath.Join(fixture.root, "replacement"), name); err != nil {
					t.Fatal(err)
				}
				delete(fixture.entries, "replacement")
			case "existence":
				plan.Operations[0].Before = Snapshot{}
			case "byte-count":
				plan.Operations[0].Before.ByteCount++
			case "digest":
				plan.Operations[0].Before.SHA256 = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			}
			if err := fixture.vector(plan, 0, true); err == nil {
				t.Fatal("independent fixture vector accepted " + mutation)
			}
		})
	}
}
