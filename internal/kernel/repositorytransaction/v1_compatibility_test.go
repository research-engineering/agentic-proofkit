package repositorytransaction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

type predecessorTarget struct {
	Path    string      `json:"path"`
	Content string      `json:"content"`
	Mode    fs.FileMode `json:"mode"`
}

type predecessorCase struct {
	Name    string              `json:"name"`
	Initial []predecessorTarget `json:"initial"`
	Targets []predecessorTarget `json:"targets"`
	Plan    string              `json:"plan"`
	Desired string              `json:"desired"`
	Journal string              `json:"journal"`
}

type predecessorFixture struct {
	SourceCommit    string            `json:"sourceCommit"`
	ReferenceRootID string            `json:"referenceRootId"`
	Cases           []predecessorCase `json:"cases"`
}

func loadPredecessorVectors(t *testing.T) (string, []predecessorCase) {
	t.Helper()
	content, err := os.ReadFile("testdata/predecessor-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(content)) != "408326cf744dda64f5cb73bc6de4cece4136ff1425f21ef850516d052c54b1e1" {
		t.Fatal("independent predecessor fixture changed")
	}
	fixture, err := admission.DecodeTypedJSON[predecessorFixture](bytes.NewReader(content), MaximumJournalBytes)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.SourceCommit != "4401e966746b4170d904cfaf23e02dd0514dd536" || len(fixture.Cases) != 9 {
		t.Fatal("predecessor provenance or coverage changed")
	}
	return fixture.ReferenceRootID, fixture.Cases
}

func TestPresentOnlyPlansPreserveIndependentPredecessorBytes(t *testing.T) {
	rootID, cases := loadPredecessorVectors(t)
	for _, fixture := range cases {
		t.Run(fixture.Name, func(t *testing.T) {
			root := t.TempDir()
			for _, initial := range fixture.Initial {
				mustWriteTestFile(t, root, initial.Path, initial.Content, initial.Mode)
			}
			targets := make([]Target, 0, len(fixture.Targets))
			for _, target := range fixture.Targets {
				targets = append(targets, Target{Path: target.Path, Content: []byte(target.Content), Mode: target.Mode})
			}
			plan, err := BuildPlan(context.Background(), root, targets)
			if err != nil {
				t.Fatal(err)
			}
			plan.RootID = rootID
			plan.DesiredStateID, err = digest.StableJSONSHA256Ref(desiredStateIdentityValue(plan))
			if err != nil {
				t.Fatal(err)
			}
			plan.TransactionID, err = digest.StableJSONSHA256Ref(planIdentityValue(plan))
			if err != nil {
				t.Fatal(err)
			}
			for _, pair := range []struct {
				actual   any
				expected string
			}{
				{plan.JSONValue(), fixture.Plan}, {desiredStateIdentityValue(plan), fixture.Desired}, {journalValue(plan), fixture.Journal},
			} {
				actual, err := stablejson.Marshal(pair.actual)
				if err != nil || string(actual) != pair.expected {
					t.Fatalf("predecessor bytes drifted: %v", err)
				}
			}
			if _, err := AdmitPlanOutput(decodePredecessorObject(t, fixture.Plan)); err != nil {
				t.Fatalf("old plan rejected: %v", err)
			}
			if _, err := admitJournal(decodePredecessorObject(t, fixture.Journal)); err != nil {
				t.Fatalf("old journal rejected: %v", err)
			}
		})
	}
}

func TestRecoverIndependentPredecessorJournalAndStagedBytes(t *testing.T) {
	rootID, cases := loadPredecessorVectors(t)
	fixture := cases[len(cases)-1]
	if fixture.Name != "recovery-pair" {
		t.Fatal("missing independent recovery fixture")
	}
	for _, action := range []string{RecoveryResume, RecoveryRollback} {
		for prefix := 0; prefix <= len(fixture.Targets); prefix++ {
			t.Run(fmt.Sprintf("%s-prefix-%d", action, prefix), func(t *testing.T) {
				rootPath := t.TempDir()
				root, actualRootID, err := openRepository(rootPath)
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				// Only root-dependent fields change. Shapes and staged bytes come
				// from the old owner, never the new journal/plan serializers.
				desired := decodePredecessorObject(t, strings.ReplaceAll(fixture.Desired, rootID, actualRootID))
				desiredID, err := digest.StableJSONSHA256Ref(desired)
				if err != nil {
					t.Fatal(err)
				}
				oldPlan := decodePredecessorObject(t, fixture.Plan)
				oldDesired := oldPlan["desiredStateId"].(string)
				oldTransaction := oldPlan["transactionId"].(string)
				identity := decodePredecessorObject(t, strings.ReplaceAll(strings.ReplaceAll(fixture.Plan, rootID, actualRootID), oldDesired, desiredID))
				delete(identity, "transactionId")
				delete(identity, "transactionKind")
				delete(identity, "nonClaims")
				transactionID, err := digest.StableJSONSHA256Ref(identity)
				if err != nil {
					t.Fatal(err)
				}
				journal := strings.NewReplacer(rootID, actualRootID, oldDesired, desiredID, oldTransaction, transactionID).Replace(fixture.Journal)
				mustWriteTestFile(t, rootPath, journalPath, journal, 0o600)
				if err := os.Chmod(rootPath+"/"+ControlRoot, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(rootPath+"/"+ControlDirectory, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(rootPath+"/"+activeDirectory, 0o700); err != nil {
					t.Fatal(err)
				}
				for index, initial := range fixture.Initial {
					actual := initial
					if index < prefix {
						actual = fixture.Targets[index]
					}
					mustWriteTestFile(t, rootPath, actual.Path, actual.Content, actual.Mode)
					mustWriteTestFile(t, rootPath, beforeObjectPath(index), initial.Content, 0o600)
					mustWriteTestFile(t, rootPath, afterObjectPath(index), fixture.Targets[index].Content, 0o600)
				}
				if err := writeMarker(root, readyMarker); err != nil {
					t.Fatal(err)
				}
				result, err := Recover(context.Background(), rootPath, transactionID, action)
				want := StateApplied
				files := fixture.Targets
				if action == RecoveryRollback {
					want, files = StateRolledBack, fixture.Initial
				}
				if err != nil || result.State != want || result.TransactionID != transactionID || result.RecoveredBy != action {
					t.Fatalf("old recovery: %#v %v", result, err)
				}
				for _, file := range files {
					assertTestFile(t, rootPath, file.Path, file.Content, file.Mode)
				}
				assertNoActiveTransaction(t, rootPath)
			})
		}
	}
}

func decodePredecessorObject(t *testing.T, text string) map[string]any {
	t.Helper()
	raw, err := admission.DecodeJSON(bytes.NewReader([]byte(text)), MaximumJournalBytes)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := raw.(map[string]any)
	if !ok {
		t.Fatal("predecessor object required")
	}
	return value
}
