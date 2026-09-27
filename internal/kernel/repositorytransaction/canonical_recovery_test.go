package repositorytransaction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

type caselessPredecessor struct{ Desired, Journal, Plan string }

func loadCaselessPredecessors(t *testing.T) map[string]caselessPredecessor {
	t.Helper()
	content, err := os.ReadFile("testdata/predecessor-caseless-v1-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(content)) != "b48eeab8d9da0ccc86425530eec3f830a6c90093e12d0c51705979942f46f873" {
		t.Fatal("frozen pre-migration fixture changed")
	}
	var fixture struct {
		SourceCommit string
		Cases        map[string]caselessPredecessor
	}
	if err := json.Unmarshal(content, &fixture); err != nil || fixture.SourceCommit != "d7fa2afcb5def437438f81058913074b175beb49" || len(fixture.Cases) != 2 {
		t.Fatal("invalid predecessor provenance")
	}
	return fixture.Cases
}

func TestCanonicalDialectPreservesFrozenV1V2Bytes(t *testing.T) {
	for version, fixture := range loadCaselessPredecessors(t) {
		t.Run(version, func(t *testing.T) {
			plan, err := AdmitPlanOutput(decodePredecessorObject(t, fixture.Plan))
			if err != nil || plan.schemaVersion() != json.Number(version) {
				t.Fatalf("legacy plan: %v", err)
			}
			journal, err := admitJournal(decodePredecessorObject(t, fixture.Journal))
			if err != nil || !reflect.DeepEqual(plan, journal) {
				t.Fatalf("legacy journal: %v", err)
			}
			for _, pair := range []struct {
				got  any
				want string
			}{{plan.JSONValue(), fixture.Plan}, {desiredStateIdentityValue(plan), fixture.Desired}, {journalValue(plan), fixture.Journal}} {
				actual, err := stablejson.Marshal(pair.got)
				if err != nil || string(actual) != pair.want {
					t.Fatal("legacy canonical bytes or identities changed")
				}
			}
			clone := clonePlan(plan)
			if clone.pathDialect() != plan.pathDialect() || clone.schemaVersion() != plan.schemaVersion() {
				t.Fatal("clone lost dialect")
			}
		})
	}
}

// Rebind only root-dependent IDs over the frozen predecessor shapes. No fresh
// writer, current key or current identity-preimage builder produces this input.
func rebindCaselessJournal(t *testing.T, fixture caselessPredecessor, rootID string) (string, Plan) {
	t.Helper()
	frozen := decodePredecessorObject(t, fixture.Plan)
	oldRoot := frozen["rootId"].(string)
	oldDesired := frozen["desiredStateId"].(string)
	oldTransaction := frozen["transactionId"].(string)
	desiredID, err := digest.StableJSONSHA256Ref(decodePredecessorObject(t, strings.ReplaceAll(fixture.Desired, oldRoot, rootID)))
	if err != nil {
		t.Fatal(err)
	}
	identity := decodePredecessorObject(t, strings.NewReplacer(oldRoot, rootID, oldDesired, desiredID).Replace(fixture.Plan))
	delete(identity, "transactionId")
	delete(identity, "transactionKind")
	delete(identity, "nonClaims")
	transactionID, err := digest.StableJSONSHA256Ref(identity)
	if err != nil {
		t.Fatal(err)
	}
	journal := strings.NewReplacer(oldRoot, rootID, oldDesired, desiredID, oldTransaction, transactionID).Replace(fixture.Journal)
	plan, err := admitJournal(decodePredecessorObject(t, journal))
	if err != nil {
		t.Fatal(err)
	}
	return journal, plan
}

func caselessPayload(operation Operation, after bool) string {
	switch operation.Path {
	case "docs/s\u015b.txt", "docs/a.txt":
		if after {
			return "new-a"
		}
		return "old-a"
	case "docs/\u00df\u0301.txt", "docs/b.txt":
		if after {
			return "new-b"
		}
		return "old-b"
	case "remove":
		return "old-d"
	default:
		return "new-c"
	}
}

type caselessScenario struct {
	version, phase, action string
	prefix                 int
}

func (scenario caselessScenario) id() string {
	return fmt.Sprintf("v%s/%s/%s/%d", scenario.version, scenario.phase, scenario.action, scenario.prefix)
}

type preparedCaselessCase struct {
	root       string
	plan       Plan
	scenario   caselessScenario
	fixture    *caselessFixture
	before     []testTreeEntry
	identities map[string]os.FileInfo
}

func seedCaselessRecovery(t *testing.T, fixture caselessPredecessor, phase string, prefix int) (preparedCaselessCase, error) {
	t.Helper()
	rootPath := t.TempDir()
	root, rootID, err := openRepository(rootPath)
	if err != nil {
		return preparedCaselessCase{}, err
	}
	defer root.Close()
	journal, plan := rebindCaselessJournal(t, fixture, rootID)
	owned := newCaselessFixture(rootPath)
	for _, operation := range plan.Operations {
		if operation.Before.Exists {
			if err := owned.create(operation.Path, []byte(caselessPayload(operation, false)), operation.Before.Mode); err != nil {
				return preparedCaselessCase{}, err
			}
		}
	}
	if err := owned.create("\u03b1\u030a\u03b9/sentinel", []byte("foreign"), 0600); err != nil {
		return preparedCaselessCase{}, err
	}
	if err := seedCaselessControl(owned, journal, phase == "preparing-temp"); err != nil {
		return preparedCaselessCase{}, err
	}
	preparing := phase == "preparing-temp" || phase == "preparing"
	if !preparing {
		for index, operation := range plan.Operations {
			if operation.Before.Exists {
				if err := owned.create(beforeObjectPath(index), []byte(caselessPayload(operation, false)), 0600); err != nil {
					return preparedCaselessCase{}, err
				}
			}
			if operation.After.Exists {
				if err := owned.create(afterObjectPath(index), []byte(caselessPayload(operation, true)), 0600); err != nil {
					return preparedCaselessCase{}, err
				}
			}
		}
		for index, directory := range plan.CreatedDirectories {
			if err := owned.mkdir(directory, 0755); err != nil {
				return preparedCaselessCase{}, err
			}
			identity, err := platformFileIdentity(owned.entries[directory].info)
			if err != nil {
				return preparedCaselessCase{}, err
			}
			// Historical fields from d7fa2af; never seed compatibility via today's writer.
			record, err := stablejson.Marshal(map[string]any{
				"directoryKind": "proofkit.repository-created-directory",
				"identity":      identity, "path": directory, "schemaVersion": json.Number("1"),
				"transactionId": plan.TransactionID,
			})
			if err != nil {
				return preparedCaselessCase{}, err
			}
			if err := owned.create(directoryOwnershipPath(index), record, 0600); err != nil {
				return preparedCaselessCase{}, err
			}
		}
		for index, operation := range plan.Operations {
			if index >= prefix {
				break
			}
			if operation.After.Exists {
				if err := owned.replace(operation.Path, []byte(caselessPayload(operation, true)), operation.After.Mode); err != nil {
					return preparedCaselessCase{}, err
				}
			} else if err := owned.remove(operation.Path); err != nil {
				return preparedCaselessCase{}, err
			}
		}
		if err := owned.create(readyMarker, nil, 0600); err != nil {
			return preparedCaselessCase{}, err
		}
		if phase == "committed" || phase == "terminal-only" {
			if err := owned.create(committedMarker, nil, 0600); err != nil {
				return preparedCaselessCase{}, err
			}
		}
		if phase == "rolled-back" {
			if err := owned.create(rolledBackMarker, nil, 0600); err != nil {
				return preparedCaselessCase{}, err
			}
		}
	}
	// This reads native identities/bytes directly, not the transaction classifier.
	if err := owned.vector(plan, prefix, preparing); err != nil {
		return preparedCaselessCase{}, err
	}
	if phase == "terminal-only" {
		terminal, err := stablejson.Marshal(map[string]any{
			"appliedCount":   json.Number(fmt.Sprint(len(plan.Operations))),
			"desiredStateId": plan.DesiredStateID, "failureClass": nil, "recoveredBy": nil,
			"schemaVersion": json.Number("2"), "state": "applied",
			"terminalKind": "proofkit.repository-terminal-receipt", "transactionId": plan.TransactionID,
		})
		if err != nil {
			return preparedCaselessCase{}, err
		}
		const historicalActive = ".agentic-proofkit/transactions/active"
		const historicalReceipt = historicalActive + "/terminal.json"
		if err := owned.create(historicalReceipt, terminal, 0600); err != nil {
			return preparedCaselessCase{}, err
		}
		if err := owned.verify(historicalReceipt); err != nil {
			return preparedCaselessCase{}, err
		}
		hexID, ok := strings.CutPrefix(plan.TransactionID, "sha256:")
		if !ok {
			return preparedCaselessCase{}, fmt.Errorf("historical transaction identity lacks digest prefix")
		}
		tombstone := ".agentic-proofkit/transactions/gc-" + hexID + "-applied"
		if err := root.Rename(filepath.FromSlash(historicalActive), filepath.FromSlash(tombstone)); err != nil {
			return preparedCaselessCase{}, err
		}
		moved := filepath.Join(rootPath, filepath.FromSlash(tombstone), "terminal.json")
		info, err := os.Lstat(moved)
		if err != nil {
			return preparedCaselessCase{}, err
		}
		content, err := os.ReadFile(moved)
		if err != nil || !os.SameFile(info, owned.entries[historicalReceipt].info) || info.Mode().Perm() != 0600 || !bytes.Equal(content, terminal) {
			return preparedCaselessCase{}, fmt.Errorf("historical terminal fixture identity, bytes or mode changed")
		}
	}
	return preparedCaselessCase{root: rootPath, plan: plan, fixture: owned, before: snapshotTestTree(t, rootPath), identities: caselessTreeIdentities(t, rootPath)}, nil
}

func TestCanonicalDialectWholeLegacyRecovery(t *testing.T) {
	required := *legacyPositiveCommand
	cases, setupErr := prepareCaselessLifecycle(t, loadCaselessPredecessors(t))
	var observed []caselessCaseEvidence
	if setupErr == nil {
		if err := qualifyCaselessOriginals(t, cases); err != nil {
			t.Fatal(err)
		}
		observed = runCaselessLifecycle(t, cases)
	} else {
		var coexistence *caselessCoexistenceError
		if !errors.As(setupErr, &coexistence) {
			t.Fatal(setupErr)
		}
		// Only failed preparation selects this branch. No Recover/assertion
		// failure can fall back, and no negative observation is a positive ID.
		for _, version := range []string{"1", "2"} {
			id := "non-representable-state-refusal/v" + version
			completed := false
			if t.Run(id, func(t *testing.T) {
				testCaselessUnmanagedRefusal(t, version, coexistence.requested, coexistence.existing, RecoveryResume, coexistence.directory, false)
				completed = true
			}) && completed {
				observed = append(observed, caselessCaseEvidence{id, false})
			}
		}
		t.Log("P3 Unicode positive corpus not established; native refusal/preservation only")
	}
	if err := validateLegacyPositiveEvidence(required, setupErr, observed); err != nil {
		t.Fatal(err)
	}
	if setupErr == nil {
		legacyPositiveCompleted = true
	}
}

func qualifyCaselessOriginals(t *testing.T, cases []preparedCaselessCase) error {
	t.Helper()
	// Reload the hash-guarded originals, independently of the preparation input.
	originals := loadCaselessPredecessors(t)
	for _, item := range cases {
		original, ok := originals[item.scenario.version]
		if !ok {
			return fmt.Errorf("positive fixture has an unknown retained version")
		}
		_, expected := rebindCaselessJournal(t, original, item.plan.RootID)
		if !reflect.DeepEqual(expected, item.plan) {
			return fmt.Errorf("positive fixture substituted the frozen Unicode corpus")
		}
	}
	return nil
}

func asciiPredecessor(fixture caselessPredecessor) caselessPredecessor {
	// A separate lifecycle control, not a substitute for the frozen Unicode
	// witnesses. Rebinding hashes the old shapes after these exact substitutions.
	replace := strings.NewReplacer("docs/s\u015b.txt", "docs/a.txt", "docs/\u00df\u0301.txt", "docs/b.txt", "\u1fb3\u030a", "z-created")
	return caselessPredecessor{Desired: replace.Replace(fixture.Desired), Journal: replace.Replace(fixture.Journal), Plan: replace.Replace(fixture.Plan)}
}

func TestCanonicalDialectWholeLegacyASCIILifecycle(t *testing.T) {
	fixtures := loadCaselessPredecessors(t)
	for version, fixture := range fixtures {
		fixtures[version] = asciiPredecessor(fixture)
	}
	testCaselessLifecycle(t, fixtures)
}

func testCaselessLifecycle(t *testing.T, fixtures map[string]caselessPredecessor) {
	t.Helper()
	cases, err := prepareCaselessLifecycle(t, fixtures)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLegacyPositiveEvidence(false, nil, runCaselessLifecycle(t, cases)); err != nil {
		t.Fatal(err)
	}
}

func prepareCaselessLifecycle(t *testing.T, fixtures map[string]caselessPredecessor) ([]preparedCaselessCase, error) {
	t.Helper()
	prepared := []preparedCaselessCase{}
	for _, version := range []string{"1", "2"} {
		fixture := fixtures[version]
		_, plan := rebindCaselessJournal(t, fixture, "sha256:"+strings.Repeat("0", 64))
		scenarios := []caselessScenario{
			{version, "preparing-temp", RecoveryRollback, 0}, {version, "preparing", RecoveryRollback, 0},
			{version, "committed", RecoveryResume, len(plan.Operations)}, {version, "rolled-back", RecoveryRollback, 0},
			{version, "terminal-only", RecoveryResume, len(plan.Operations)},
		}
		for prefix := 0; prefix <= len(plan.Operations); prefix++ {
			for _, action := range []string{RecoveryResume, RecoveryRollback} {
				scenarios = append(scenarios, caselessScenario{version, "ready", action, prefix})
			}
		}
		for _, scenario := range scenarios {
			item, err := seedCaselessRecovery(t, fixture, scenario.phase, scenario.prefix)
			if err != nil {
				return nil, err
			}
			item.scenario = scenario
			prepared = append(prepared, item)
		}
	}
	return prepared, nil
}

func runCaselessLifecycle(t *testing.T, cases []preparedCaselessCase) []caselessCaseEvidence {
	t.Helper()
	observed := []caselessCaseEvidence{}
	for _, item := range cases {
		test, rootPath, retained := item.scenario, item.root, item.plan
		completed := false
		if t.Run(test.id(), func(t *testing.T) {
			assertCaselessTreeUnchanged(t, rootPath, item.before, item.identities)
			inspection, err := InspectControlState(context.Background(), rootPath)
			if err != nil || inspection.State != ControlStateRecoverable || inspection.TransactionID != retained.TransactionID {
				t.Fatalf("legacy inspection: %#v %v", inspection, err)
			}
			result, err := Recover(context.Background(), rootPath, retained.TransactionID, test.action)
			want, count := StateApplied, len(retained.Operations)
			if test.action == RecoveryRollback {
				want, count = StateRolledBack, 0
			}
			if err != nil || result.State != want || result.TransactionID != retained.TransactionID || result.RecoveredBy != test.action || !result.AppliedCountKnown || result.AppliedCount != count {
				t.Fatalf("recovery: %#v %v", result, err)
			}
			for _, operation := range retained.Operations {
				snapshot, after := operation.After, true
				if test.action == RecoveryRollback {
					snapshot, after = operation.Before, false
				}
				if snapshot.Exists {
					assertTestFile(t, rootPath, operation.Path, caselessPayload(operation, after), snapshot.Mode)
				} else {
					assertAbsentTestPath(t, rootPath, operation.Path)
				}
			}
			if test.action == RecoveryRollback {
				assertAbsentTestPath(t, rootPath, retained.CreatedDirectories[0])
			}
			if err := item.fixture.verify("\u03b1\u030a\u03b9/sentinel"); err != nil {
				t.Fatal(err)
			}
			if err := item.fixture.verify("\u03b1\u030a\u03b9"); err != nil {
				t.Fatal(err)
			}
			assertNoActiveTransaction(t, rootPath)
			root, _, err := openRepository(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			receipt, err := loadTerminalReceipt(root, terminalTombstonePath(retained.TransactionID, want))
			if err != nil || receipt.DesiredStateID != retained.DesiredStateID || terminalReceiptValue(receipt)["schemaVersion"] != json.Number("2") {
				t.Fatalf("receipt lost legacy desired identity: %v", err)
			}
			before, identities := snapshotTestTree(t, rootPath), caselessTreeIdentities(t, rootPath)
			repeated, err := Recover(context.Background(), rootPath, retained.TransactionID, test.action)
			if err != nil || repeated != result {
				t.Fatalf("repeat: %#v %v", repeated, err)
			}
			assertCaselessTreeUnchanged(t, rootPath, before, identities)
			completed = true
		}) && completed {
			observed = append(observed, caselessCaseEvidence{test.id(), true})
		}
	}
	return observed
}

func TestCanonicalDialectFreshMergeSplitAndRecovery(t *testing.T) {
	if _, err := BuildPlan(context.Background(), t.TempDir(), []Target{{Path: "docs/s\u015b", Mode: 0644}, {Path: "docs/\u00df\u0301", Mode: 0644}}); err == nil {
		t.Fatal("v3 admitted merged class")
	}
	for _, action := range []string{RecoveryResume, RecoveryRollback} {
		t.Run(action, func(t *testing.T) {
			root := t.TempDir()
			targets := []Target{{Path: "\u1fb3\u030a/a", Content: []byte("first"), Mode: 0644}, {Path: "\u03b1\u03b9\u030a/b", Content: []byte("second"), Mode: 0600}}
			plan, err := BuildPlan(context.Background(), root, targets)
			if err != nil || plan.schemaVersion() != "3" {
				t.Fatalf("fresh split: %v", err)
			}
			leaveInterruptedPrefix(t, root, plan, 1)
			result, err := Recover(context.Background(), root, plan.TransactionID, action)
			want := StateApplied
			if action == RecoveryRollback {
				want = StateRolledBack
			}
			if err != nil || result.State != want {
				t.Fatalf("v3 recovery: %#v %v", result, err)
			}
			handle, _, err := openRepository(root)
			if err != nil {
				t.Fatal(err)
			}
			defer handle.Close()
			receipt, err := loadTerminalReceipt(handle, terminalTombstonePath(plan.TransactionID, want))
			if err != nil || receipt.DesiredStateID != plan.DesiredStateID || terminalReceiptValue(receipt)["schemaVersion"] != json.Number("2") {
				t.Fatal("v3 transaction changed the independent receipt version or desired identity")
			}
			for _, target := range targets {
				if action == RecoveryResume {
					assertTestFile(t, root, target.Path, string(target.Content), target.Mode)
				} else {
					assertAbsentTestPath(t, root, target.Path)
				}
			}
		})
	}
}

func TestCanonicalDialectVersionForgeriesAndNativeAuthority(t *testing.T) {
	root := t.TempDir()
	plan, err := BuildPlan(context.Background(), root, []Target{{Path: "a", Mode: 0644}})
	if err != nil {
		t.Fatal(err)
	}
	for _, forged := range []any{nil, 0, 1, 2, 3, float64(3), "3", json.Number("0"), json.Number("4"), json.Number("3.0"), json.Number("3e0"), json.Number("03"), json.Number("1"), json.Number("2")} {
		wire := plan.JSONValue()
		wire["schemaVersion"] = forged
		if _, err := AdmitPlanOutput(wire); err == nil {
			t.Fatalf("forged version admitted: %#v", forged)
		}
	}
	for _, version := range []json.Number{"", "1", "2", "3", "4"} {
		copy := clonePlan(plan)
		copy.version = version
		if version == "3" {
			copy = readmittedConstructionPlan(t, plan)
		}
		assertConstructionRejected(t, root, copy)
	}
	// Recomputed IDs make a different descriptive record, never Apply authority.
	wire := journalValue(plan)
	wire["schemaVersion"] = json.Number("1")
	desired := desiredStateIdentityValue(plan)
	desired["schemaVersion"] = json.Number("1")
	wire["desiredStateId"], err = digest.StableJSONSHA256Ref(desired)
	if err != nil {
		t.Fatal(err)
	}
	identity := map[string]any{}
	for key, value := range wire {
		if key != "journalKind" && key != "transactionId" {
			identity[key] = value
		}
	}
	wire["transactionId"], err = digest.StableJSONSHA256Ref(identity)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := admitJournal(wire)
	if err != nil {
		t.Fatal(err)
	}
	assertConstructionRejected(t, root, legacy)
	before, err := stablejson.Marshal(legacy.JSONValue())
	if err != nil {
		t.Fatal(err)
	}
	wire["operations"].([]any)[0].(map[string]any)["path"] = "mutated"
	after, err := stablejson.Marshal(legacy.JSONValue())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("admitted legacy reread caller data")
	}
}

func TestCanonicalDialectFreshReplayRejectsLegacyReceipt(t *testing.T) {
	fixture := asciiPredecessor(loadCaselessPredecessors(t)["1"])
	prepared, err := seedCaselessRecovery(t, fixture, "terminal-only", 3)
	if err != nil {
		t.Fatal(err)
	}
	root, retained := prepared.root, prepared.plan
	if result, err := Recover(context.Background(), root, retained.TransactionID, RecoveryResume); err != nil || result.State != StateApplied {
		t.Fatalf("legacy cleanup: %#v %v", result, err)
	}
	targets := []Target{}
	for _, operation := range retained.Operations {
		targets = append(targets, Target{Path: operation.Path, Content: []byte(caselessPayload(operation, true)), Mode: operation.After.Mode})
	}
	fresh, err := BuildPlan(context.Background(), root, targets)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayApplied(context.Background(), root, fresh, retained.TransactionID); !errors.Is(err, ErrReplayMismatch) {
		t.Fatalf("legacy receipt replayed as v3: %v", err)
	}
	oldDesired := desiredStateIdentityValue(fresh)
	oldDesired["schemaVersion"] = json.Number("1")
	oldID, err := digest.StableJSONSHA256Ref(oldDesired)
	if err != nil || oldID != retained.DesiredStateID || fresh.DesiredStateID == retained.DesiredStateID {
		t.Fatal("replay mismatch was not isolated to the version operand")
	}
}
