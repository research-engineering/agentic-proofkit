package app

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func testIntegrationRecoveryObservationStreams(t *testing.T) {
	for _, phase := range []string{"preparing-temp", "preparing", "ready", "committed", "rolled-back"} {
		for _, mutation := range []string{"none", "content", "directory", "parent"} {
			for _, command := range []struct {
				name  string
				route []string
			}{
				{"integration", []string{"integration", "recover"}},
				{"adoption", []string{"adopt", "materialize", "recover"}},
			} {
				for _, format := range []string{"json", "text"} {
					t.Run(phase+"/"+mutation+"/"+command.name+"/"+format, func(t *testing.T) {
						root, transaction, action := recoveryCLIFixture(t, phase)
						target := filepath.Join(root, "source/item")
						if mutation != "none" {
							if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
								t.Fatal(err)
							}
						}
						switch mutation {
						case "content":
							if err := os.WriteFile(target, []byte("foreign caller content"), 0o600); err != nil {
								t.Fatal(err)
							}
						case "directory":
							if err := os.Mkdir(target, 0o700); err != nil {
								t.Fatal(err)
							}
						case "parent":
							if err := os.Remove(filepath.Dir(target)); err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(filepath.Dir(target), []byte("foreign parent"), 0o600); err != nil {
								t.Fatal(err)
							}
						}
						before := recoveryCLITree(t, root)
						args := append(command.route, "--repo-root", root, "--transaction", transaction, "--action", action, "--format", format)
						code, stdout, stderr := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
						if mutation == "directory" || mutation == "parent" {
							if code != 1 || stdout != "" || !strings.Contains(stderr, "repository transaction") {
								t.Fatalf("operational recovery error became a packet: code=%d stdout=%q stderr=%q", code, stdout, stderr)
							}
						} else {
							wantCode := 0
							if mutation == "content" {
								wantCode = 1
							}
							if code != wantCode || stdout == "" || stderr != "" {
								t.Fatalf("classified recovery stream changed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
							}
							if format == "json" {
								value := decodeCLIJSON(t, stdout).(map[string]any)
								want := "passed"
								if mutation == "content" {
									want = "recovery_required"
								}
								if value["state"] != want {
									t.Fatal("recovery fixture did not reach its intended state")
								}
							}
						}
						if mutation != "none" && !reflect.DeepEqual(before, recoveryCLITree(t, root)) {
							t.Fatal("rejected recovery mutated target or control state")
						}
						for _, forbidden := range []string{root, "foreign caller content", "foreign parent"} {
							if strings.Contains(stdout+stderr, forbidden) {
								t.Fatal("recovery disclosed caller path or content")
							}
						}
					})
				}
			}
		}
	}
}

func recoveryCLIFixture(t *testing.T, phase string) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "source"), 0o700); err != nil {
		t.Fatal(err)
	}
	before := []byte("original")
	if err := os.WriteFile(filepath.Join(root, "source/item"), before, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := repositorytransaction.BuildPlan(context.Background(), root, []repositorytransaction.Target{{Path: "source/item", Absent: true}})
	if err != nil {
		t.Fatal(err)
	}
	// Author a pending journal independently of the execution path. Every phase
	// has an unmodified positive CLI control before its one-operand mutations.
	journal := plan.JSONValue()
	delete(journal, "transactionKind")
	delete(journal, "nonClaims")
	journal["journalKind"] = "proofkit.repository-write-journal"
	encoded, err := stablejson.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(root, repositorytransaction.ControlDirectory, "active")
	if err := os.MkdirAll(active, 0o700); err != nil {
		t.Fatal(err)
	}
	journalName := "journal.json"
	if phase == "preparing-temp" {
		journalName = "journal.tmp"
	}
	files := map[string][]byte{journalName: encoded}
	if phase != "preparing-temp" {
		files["before-000.bin"] = before
	}
	action := "rollback"
	if phase != "preparing" && phase != "preparing-temp" {
		files["ready"] = nil
	}
	if phase == "committed" {
		action = "resume"
		files["committed"] = nil
		if err := os.Remove(filepath.Join(root, "source/item")); err != nil {
			t.Fatal(err)
		}
	} else if phase == "rolled-back" {
		files["rolled-back"] = nil
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(active, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, plan.TransactionID, action
}

type recoveryCLIEntry struct {
	mode    fs.FileMode
	content string
}

func recoveryCLITree(t *testing.T, root string) map[string]recoveryCLIEntry {
	t.Helper()
	entries := map[string]recoveryCLIEntry{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		var content []byte
		if info.Mode().IsRegular() {
			content, err = os.ReadFile(path)
		}
		entries[path] = recoveryCLIEntry{mode: info.Mode(), content: string(content)}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}
