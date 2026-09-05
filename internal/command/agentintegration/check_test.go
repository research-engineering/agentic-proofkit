package agentintegration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/rootpath"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const checkPrivateSentinel = "private-check-observation-92a61"

func checkTestDocument(t *testing.T, tool string) Document {
	t.Helper()
	var capabilities []Capability
	for _, command := range ConsumedCommands() {
		capabilities = append(capabilities, Capability{
			Command: command, Route: []string{command}, ContractDigest: digest.SHA256TextRef("check-fixture:" + command),
		})
	}
	document, err := Source(tool, capabilities)
	if err != nil {
		t.Fatal("source fixture failed")
	}
	return document
}

func checkWrite(t *testing.T, path, content string) {
	t.Helper()
	checkMkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal("fixture write failed")
	}
}

func checkMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal("fixture directory creation failed")
	}
}

func checkSymlink(t *testing.T, target, path string) {
	t.Helper()
	checkMkdir(t, filepath.Dir(path))
	if err := os.Symlink(target, path); err != nil {
		t.Fatal("fixture symlink creation failed")
	}
}

type checkTestEntry struct {
	mode    fs.FileMode
	modTime time.Time
	content string
}

func checkTree(t *testing.T, root string) map[string]checkTestEntry {
	t.Helper()
	entries := map[string]checkTestEntry{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := checkTestEntry{mode: info.Mode(), modTime: info.ModTime()}
		switch {
		case info.Mode().IsRegular():
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value.content = string(content)
		case info.Mode()&fs.ModeSymlink != 0:
			value.content, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		entries[path] = value
		return nil
	})
	if err != nil {
		t.Fatal("fixture snapshot failed")
	}
	return entries
}

func checkUnchanged(t *testing.T, root string, before map[string]checkTestEntry) {
	t.Helper()
	if !reflect.DeepEqual(before, checkTree(t, root)) {
		t.Fatal("check changed the protected filesystem snapshot")
	}
}

func checkNoDisclosure(t *testing.T, result CheckResult, err error, private ...string) {
	t.Helper()
	encoded, marshalErr := json.Marshal(result.JSONValue())
	if marshalErr != nil {
		t.Fatal("check report is not JSON serializable")
	}
	output := string(encoded) + result.Text()
	if err != nil {
		output += err.Error()
	}
	for _, secret := range append(private, checkPrivateSentinel, digest.SHA256TextRef(checkPrivateSentinel)) {
		if secret != "" && strings.Contains(output, secret) {
			t.Fatal("check disclosed protected data")
		}
	}
	if strings.Contains(output, "passed") {
		t.Fatal("freshness was promoted to passed")
	}
}

func checkWantError(t *testing.T, result CheckResult, err error, private ...string) {
	t.Helper()
	checkNoDisclosure(t, result, err, private...)
	if err == nil || result != (CheckResult{}) || !strings.Contains(err.Error(), "integration check operation") {
		t.Fatal("expected normalized operation error and zero result")
	}
}

func TestCheckStatesAreReadOnlyAndPrivate(t *testing.T) {
	for _, tool := range []string{"codex", "claude"} {
		document := checkTestDocument(t, tool)
		cases := []struct {
			name    string
			state   string
			content string
		}{
			{name: "missing", state: "missing"},
			{name: "missing leaf", state: "missing"},
			{name: "current", state: "current", content: document.Content()},
			{name: "unknown", state: "stale", content: checkPrivateSentinel},
			{name: "empty", state: "stale"},
			{name: "exact bound", state: "stale", content: strings.Repeat("a", maximumCheckBytes)},
			{name: "oversized", state: "invalid", content: strings.Repeat("a", maximumCheckBytes+1)},
			{name: "invalid UTF8", state: "invalid", content: checkPrivateSentinel + "\xff"},
			{name: "NUL", state: "invalid", content: checkPrivateSentinel + "\x00"},
			{name: "directory", state: "invalid"},
			{name: "non directory parent", state: "invalid"},
		}
		for _, test := range cases {
			t.Run(tool+"/"+test.name, func(t *testing.T) {
				sandbox := t.TempDir()
				root := filepath.Join(sandbox, "repository")
				home := filepath.Join(sandbox, "home")
				checkMkdir(t, root)
				t.Setenv("HOME", home)
				t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
				t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude"))
				otherTool := "claude"
				if tool == "claude" {
					otherTool = "codex"
				}
				other := checkTestDocument(t, otherTool)
				checkWrite(t, filepath.Join(root, other.path), checkPrivateSentinel)
				checkWrite(t, filepath.Join(root, "AGENTS.md"), checkPrivateSentinel)
				for _, directory := range []string{".agents", ".codex", ".claude"} {
					checkWrite(t, filepath.Join(home, directory, "skills/agentic-proofkit/SKILL.md"), checkPrivateSentinel)
				}
				selected := filepath.Join(root, document.path)
				switch test.name {
				case "missing":
				case "missing leaf":
					checkMkdir(t, filepath.Dir(selected))
				case "directory":
					checkMkdir(t, selected)
				case "non directory parent":
					checkWrite(t, filepath.Join(root, strings.Split(document.path, "/")[0]), checkPrivateSentinel)
				default:
					checkWrite(t, selected, test.content)
				}
				before := checkTree(t, sandbox)
				result, err := Check(context.Background(), root, document)
				checkNoDisclosure(t, result, err, root)
				if err != nil || result.State() != test.state {
					t.Fatal("unexpected freshness classification")
				}
				if test.state != "current" && test.content != "" {
					checkNoDisclosure(t, result, err, digest.SHA256TextRef(test.content))
				}
				checkUnchanged(t, sandbox, before)
			})
		}
	}
}

func TestCheckProjectionHasOnlyAdmittedFields(t *testing.T) {
	document := checkTestDocument(t, "codex")
	result, err := Check(context.Background(), t.TempDir(), document)
	if err != nil {
		t.Fatal("check failed")
	}
	value := result.JSONValue()
	if _, err := stablejson.Marshal(value); err != nil {
		t.Fatalf("check output is not a canonical JSON value: %v", err)
	}
	expected := map[string]any{
		"schemaVersion": 1, "kind": "proofkit.integration-check.v1", "tool": "codex",
		"targetPath": document.path, "integrationId": document.identity,
		"expectedContentDigest": document.contentDigest, "state": "missing", "nonClaims": checkNonClaims(),
	}
	if !reflect.DeepEqual(value, expected) || !strings.Contains(result.Text(), "missing") {
		t.Fatal("check projection differs from its exact contract")
	}
	value["state"] = "passed"
	value["nonClaims"].([]any)[0] = "changed"
	if !reflect.DeepEqual(result.JSONValue(), expected) || result.State() != "missing" {
		t.Fatal("projection mutation changed the private result")
	}
}

func TestCheckRejectsZeroDocumentBeforeInspection(t *testing.T) {
	dependencies := nativeCheckDependencies()
	dependencies.openFile = func(*repositorytransaction.InspectionLease, string) (repositorytransaction.InspectionFile, rootpath.RouteObservation, error) {
		t.Fatal("zero document reached file inspection")
		return nil, rootpath.RouteObservation{}, nil
	}
	result, err := checkWithDependencies(context.Background(), checkPrivateSentinel, Document{}, dependencies)
	checkWantError(t, result, err)
	if !strings.Contains(err.Error(), "source document") {
		t.Fatal("zero document was not rejected before root admission")
	}
}

func TestCheckInvalidRootsAreOperationErrors(t *testing.T) {
	document := checkTestDocument(t, "codex")
	sandbox := t.TempDir()
	file := filepath.Join(sandbox, "file")
	link := filepath.Join(sandbox, "link")
	checkWrite(t, file, checkPrivateSentinel)
	checkSymlink(t, sandbox, link)
	for _, root := range []string{"", filepath.Join(sandbox, "absent"), file, link} {
		result, err := Check(context.Background(), root, document)
		checkWantError(t, result, err, root)
	}
}

func TestCheckRejectsEverySymlinkComponentWithoutFollowing(t *testing.T) {
	document := checkTestDocument(t, "codex")
	components := strings.Split(document.path, "/")
	for index := range components {
		t.Run(components[index], func(t *testing.T) {
			sandbox := t.TempDir()
			root := filepath.Join(sandbox, "repository")
			outside := filepath.Join(sandbox, "outside")
			checkMkdir(t, root)
			target := outside
			if index < len(components)-1 {
				checkWrite(t, filepath.Join(outside, filepath.Join(components[index+1:]...)), checkPrivateSentinel)
			} else {
				checkWrite(t, target, checkPrivateSentinel)
			}
			checkSymlink(t, target, filepath.Join(root, filepath.Join(components[:index+1]...)))
			before := checkTree(t, sandbox)
			result, err := Check(context.Background(), root, document)
			checkNoDisclosure(t, result, err, root, outside)
			if err != nil || result.State() != "invalid" {
				t.Fatal("symlink component was not invalid")
			}
			checkUnchanged(t, sandbox, before)
		})
	}
}

func TestCheckPortableAliasesAreOperationErrors(t *testing.T) {
	document := checkTestDocument(t, "codex")
	for index := range strings.Split(document.path, "/") {
		components := strings.Split(document.path, "/")
		components[index] = strings.ToUpper(components[index])
		t.Run(components[index], func(t *testing.T) {
			root := t.TempDir()
			checkWrite(t, filepath.Join(root, filepath.Join(components...)), checkPrivateSentinel)
			before := checkTree(t, root)
			result, err := Check(context.Background(), root, document)
			checkWantError(t, result, err, root)
			checkUnchanged(t, root, before)
		})
	}
}

type checkTestFile struct {
	repositorytransaction.InspectionFile
	read  func([]byte) (int, error)
	stat  func() (fs.FileInfo, error)
	close func() error
}

func (file checkTestFile) Read(buffer []byte) (int, error) {
	if file.read != nil {
		return file.read(buffer)
	}
	return file.InspectionFile.Read(buffer)
}

func (file checkTestFile) Stat() (fs.FileInfo, error) {
	if file.stat != nil {
		return file.stat()
	}
	return file.InspectionFile.Stat()
}

func (file checkTestFile) Close() error {
	if file.close != nil {
		return file.close()
	}
	return file.InspectionFile.Close()
}

func TestCheckOpenErrorsAreNotMissingOrInvalid(t *testing.T) {
	document := checkTestDocument(t, "codex")
	cases := []struct {
		name string
		err  error
	}{
		{"permission", fs.ErrPermission},
		{"IO", errors.New(checkPrivateSentinel)},
		{"route changed", repositorytransaction.ErrInspectionRouteChanged},
		{"alias", rootpath.ErrAmbiguousRoute},
		{"missing with cleanup failure", errors.Join(fs.ErrNotExist, rootpath.ErrTraversalCleanup)},
		{"unsafe with cleanup failure", errors.Join(repositorytransaction.ErrUnsafeInspectionRoute, repositorytransaction.ErrReadCleanup)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			dependencies := nativeCheckDependencies()
			dependencies.openFile = func(*repositorytransaction.InspectionLease, string) (repositorytransaction.InspectionFile, rootpath.RouteObservation, error) {
				return nil, rootpath.RouteObservation{}, &fs.PathError{Op: checkPrivateSentinel, Path: root, Err: test.err}
			}
			before := checkTree(t, root)
			result, err := checkWithDependencies(context.Background(), root, document, dependencies)
			checkWantError(t, result, err, root)
			if strings.Contains(test.name, "cleanup failure") && !errors.Is(err, repositorytransaction.ErrReadCleanup) {
				t.Fatal("route cleanup failure was not retained")
			}
			checkUnchanged(t, root, before)
		})
	}
	t.Run("wrapped absence", func(t *testing.T) {
		root := t.TempDir()
		dependencies := nativeCheckDependencies()
		dependencies.openFile = func(lease *repositorytransaction.InspectionLease, path string) (repositorytransaction.InspectionFile, rootpath.RouteObservation, error) {
			file, route, err := lease.OpenObservedExactRegularFile(path)
			if file != nil || !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("fixture did not observe ordinary absence")
			}
			return nil, route, &fs.PathError{Op: checkPrivateSentinel, Path: root, Err: err}
		}
		result, err := checkWithDependencies(context.Background(), root, document, dependencies)
		checkNoDisclosure(t, result, err, root)
		if err != nil || result.State() != "missing" {
			t.Fatal("ordinary absence was not missing")
		}
	})
}

func TestCheckPermissionDeniedIsNotMissing(t *testing.T) {
	root := t.TempDir()
	document := checkTestDocument(t, "codex")
	selected := filepath.Join(root, document.path)
	checkWrite(t, selected, checkPrivateSentinel)
	before := checkTree(t, root)
	if err := os.Chmod(selected, 0); err != nil {
		t.Fatal("fixture permission change failed")
	}
	t.Cleanup(func() { _ = os.Chmod(selected, 0o600) })
	dependencies := nativeCheckDependencies()
	probe, probeErr := os.Open(selected)
	if probeErr == nil {
		if err := probe.Close(); err != nil {
			t.Fatal("permission probe cleanup failed")
		}
		// Privileged filesystems cannot supply a real denied-read operand.
		dependencies.openFile = func(*repositorytransaction.InspectionLease, string) (repositorytransaction.InspectionFile, rootpath.RouteObservation, error) {
			return nil, rootpath.RouteObservation{}, &fs.PathError{Op: "open", Path: selected, Err: fs.ErrPermission}
		}
	} else if !errors.Is(probeErr, fs.ErrPermission) {
		t.Fatal("permission fixture failed for an unrelated reason")
	}
	result, err := checkWithDependencies(context.Background(), root, document, dependencies)
	checkWantError(t, result, err, root, selected)
	if err := os.Chmod(selected, 0o600); err != nil {
		t.Fatal("fixture permission restoration failed")
	}
	checkUnchanged(t, root, before)
}

func TestCheckDetectsChangesWithinAnObservation(t *testing.T) {
	document := checkTestDocument(t, "codex")
	for _, scenario := range []string{"size drift", "short read", "mode drift"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			selected := filepath.Join(root, document.path)
			checkWrite(t, selected, document.Content())
			dependencies := nativeCheckDependencies()
			dependencies.openFile = func(lease *repositorytransaction.InspectionLease, path string) (repositorytransaction.InspectionFile, rootpath.RouteObservation, error) {
				file, route, err := lease.OpenObservedExactRegularFile(path)
				if err != nil {
					return nil, route, err
				}
				changed := false
				return checkTestFile{InspectionFile: file, read: func(buffer []byte) (int, error) {
					if !changed {
						changed = true
						switch scenario {
						case "size drift":
							checkWrite(t, selected, document.Content()+"changed")
						case "short read":
							return 0, io.EOF
						case "mode drift":
							if err := os.Chmod(selected, 0o400); err != nil {
								t.Fatal("fixture mode change failed")
							}
						}
					}
					return file.Read(buffer)
				}}, route, nil
			}
			result, err := checkWithDependencies(context.Background(), root, document, dependencies)
			checkWantError(t, result, err, root)
			if !strings.Contains(err.Error(), "changed while reading") {
				t.Fatal("intra-observation drift was not detected")
			}
		})
	}
}

func TestCheckReobservesBytesStateAndOpenedIdentityIndependently(t *testing.T) {
	document := checkTestDocument(t, "codex")
	for _, scenario := range []string{"bytes only", "invalid bytes only", "oversized prefix only", "state only", "reverse state only", "file identity only"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			selected := filepath.Join(root, document.path)
			content := checkPrivateSentinel + "A"
			if scenario == "invalid bytes only" {
				content += "\x00"
			}
			if scenario == "oversized prefix only" {
				content += strings.Repeat("x", maximumCheckBytes)
			}
			switch scenario {
			case "state only":
				checkMkdir(t, filepath.Dir(selected))
			case "reverse state only":
				checkMkdir(t, selected)
			default:
				checkWrite(t, selected, content)
			}
			dependencies := nativeCheckDependencies()
			opens := 0
			dependencies.openFile = func(lease *repositorytransaction.InspectionLease, path string) (repositorytransaction.InspectionFile, rootpath.RouteObservation, error) {
				opens++
				if opens == 2 {
					switch scenario {
					case "state only":
						checkMkdir(t, selected)
					case "reverse state only":
						if err := os.Remove(selected); err != nil {
							t.Fatal("fixture removal failed")
						}
					default:
						before, err := os.Stat(selected)
						if err != nil {
							t.Fatal("fixture stat failed")
						}
						replacement := strings.Replace(content, "A", "B", 1)
						if scenario == "file identity only" {
							if err := os.Rename(selected, selected+".saved"); err != nil {
								t.Fatal("fixture rename failed")
							}
							replacement = content
						}
						checkWrite(t, selected, replacement)
						if err := os.Chtimes(selected, before.ModTime(), before.ModTime()); err != nil {
							t.Fatal("fixture timestamp restoration failed")
						}
						after, err := os.Stat(selected)
						if err != nil || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
							t.Fatal("fixture did not preserve metadata")
						}
						if os.SameFile(before, after) == (scenario == "file identity only") {
							t.Fatal("fixture did not isolate opened-file identity")
						}
					}
				}
				return lease.OpenObservedExactRegularFile(path)
			}
			result, err := checkWithDependencies(context.Background(), root, document, dependencies)
			checkWantError(t, result, err, root)
			if opens != 2 {
				t.Fatal("drift test did not reach exactly two observations")
			}
		})
	}
}

func TestCheckVerifiesRootAfterBothObservations(t *testing.T) {
	sandbox := t.TempDir()
	root := filepath.Join(sandbox, "repository")
	document := checkTestDocument(t, "codex")
	checkWrite(t, filepath.Join(root, document.path), document.Content())
	dependencies := nativeCheckDependencies()
	closes := 0
	dependencies.openFile = func(lease *repositorytransaction.InspectionLease, path string) (repositorytransaction.InspectionFile, rootpath.RouteObservation, error) {
		file, route, err := lease.OpenObservedExactRegularFile(path)
		if err != nil {
			return nil, route, err
		}
		return checkTestFile{InspectionFile: file, close: func() error {
			closeErr := file.Close()
			closes++
			if closes == 2 {
				if err := os.Rename(root, root+".saved"); err != nil {
					t.Fatal("fixture root replacement failed")
				}
				checkMkdir(t, root)
			}
			return closeErr
		}}, route, nil
	}
	result, err := checkWithDependencies(context.Background(), root, document, dependencies)
	checkWantError(t, result, err, root)
	if closes != 2 || !strings.Contains(err.Error(), "repository root changed") {
		t.Fatal("root identity was not checked after both file observations")
	}
}

func TestCheckUsesOneLeaseAndStrictReadBounds(t *testing.T) {
	root := t.TempDir()
	document := checkTestDocument(t, "codex")
	checkWrite(t, filepath.Join(root, document.path), strings.Repeat("a", maximumCheckBytes*2))
	dependencies := nativeCheckDependencies()
	var pinned *repositorytransaction.InspectionLease
	opens, closes, totalRead, leaseCloses := 0, 0, 0, 0
	dependencies.openFile = func(lease *repositorytransaction.InspectionLease, path string) (repositorytransaction.InspectionFile, rootpath.RouteObservation, error) {
		if pinned != nil && pinned != lease || path != document.path {
			t.Fatal("check changed its root lease or selected path")
		}
		pinned = lease
		opens++
		file, route, err := lease.OpenObservedExactRegularFile(path)
		if err != nil {
			return nil, route, err
		}
		read := 0
		return checkTestFile{InspectionFile: file, read: func(buffer []byte) (int, error) {
			if read+len(buffer) > maximumCheckBytes {
				t.Fatal("read request exceeded the observation budget")
			}
			n, err := file.Read(buffer)
			read += n
			totalRead += n
			return n, err
		}, close: func() error {
			closes++
			return file.Close()
		}}, route, nil
	}
	dependencies.closeLease = func(lease *repositorytransaction.InspectionLease) error {
		leaseCloses++
		if closes != 2 || lease != pinned {
			t.Fatal("lease closed before its files")
		}
		return lease.Close()
	}
	result, err := checkWithDependencies(context.Background(), root, document, dependencies)
	if err != nil || result.State() != "invalid" || opens != 2 || closes != 2 || leaseCloses != 1 || totalRead != maximumCheckBytes*2 {
		t.Fatal("check violated bounded single-lease observation")
	}
}

func TestCheckCancellationBeforeAndAfterObservation(t *testing.T) {
	document := checkTestDocument(t, "codex")
	t.Run("before", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := Check(ctx, checkPrivateSentinel, document)
		checkWantError(t, result, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatal("pre-cancellation was not preserved before root admission")
		}
	})
	for _, state := range []string{"missing", "current", "stale", "invalid"} {
		t.Run("late/"+state, func(t *testing.T) {
			root := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checkStateFixture(t, root, document, state)
			before := checkTree(t, root)
			dependencies := nativeCheckDependencies()
			dependencies.closeLease = func(lease *repositorytransaction.InspectionLease) error {
				err := lease.Close()
				cancel()
				return err
			}
			result, err := checkWithDependencies(ctx, root, document, dependencies)
			checkWantError(t, result, err, root)
			if !errors.Is(err, context.Canceled) {
				t.Fatal("late cancellation was not preserved")
			}
			checkUnchanged(t, root, before)
		})
	}
}

func checkStateFixture(t *testing.T, root string, document Document, state string) {
	t.Helper()
	switch state {
	case "missing":
	case "current":
		checkWrite(t, filepath.Join(root, document.path), document.Content())
	case "stale":
		checkWrite(t, filepath.Join(root, document.path), checkPrivateSentinel)
	case "invalid":
		checkMkdir(t, filepath.Join(root, document.path))
	default:
		t.Fatal("unknown fixture state")
	}
}

func TestCheckCleanupFailureInvalidatesEveryState(t *testing.T) {
	document := checkTestDocument(t, "codex")
	for _, state := range []string{"missing", "current", "stale", "invalid"} {
		t.Run(state, func(t *testing.T) {
			root := t.TempDir()
			checkStateFixture(t, root, document, state)
			before := checkTree(t, root)
			dependencies := nativeCheckDependencies()
			dependencies.closeLease = func(lease *repositorytransaction.InspectionLease) error {
				if err := lease.Close(); err != nil {
					t.Fatal("real lease cleanup failed")
				}
				return errors.New(checkPrivateSentinel)
			}
			result, err := checkWithDependencies(context.Background(), root, document, dependencies)
			checkWantError(t, result, err, root)
			if !errors.Is(err, repositorytransaction.ErrReadCleanup) {
				t.Fatal("lease cleanup failure was not retained")
			}
			checkUnchanged(t, root, before)
		})
	}
}

func TestCheckFileIOAndCleanupFailures(t *testing.T) {
	document := checkTestDocument(t, "codex")
	for _, scenario := range []string{"read", "first stat", "second stat", "first close", "second close", "read and close", "cancel and close"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			checkWrite(t, filepath.Join(root, document.path), document.Content())
			before := checkTree(t, root)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dependencies := nativeCheckDependencies()
			opens, closes, leaseCloses := 0, 0, 0
			dependencies.openFile = func(lease *repositorytransaction.InspectionLease, path string) (repositorytransaction.InspectionFile, rootpath.RouteObservation, error) {
				opens++
				file, route, err := lease.OpenObservedExactRegularFile(path)
				if err != nil {
					return nil, route, err
				}
				stats := 0
				return checkTestFile{InspectionFile: file, read: func(buffer []byte) (int, error) {
					if scenario == "read" || scenario == "read and close" {
						return 0, errors.New(checkPrivateSentinel)
					}
					return file.Read(buffer)
				}, stat: func() (fs.FileInfo, error) {
					stats++
					if scenario == "first stat" && stats == 1 || scenario == "second stat" && stats == 2 {
						return nil, errors.New(checkPrivateSentinel)
					}
					return file.Stat()
				}, close: func() error {
					closes++
					if err := file.Close(); err != nil {
						t.Fatal("real file cleanup failed")
					}
					if scenario == "cancel and close" {
						cancel()
					}
					if scenario == "first close" || scenario == "second close" && opens == 2 || scenario == "read and close" || scenario == "cancel and close" {
						return errors.New(checkPrivateSentinel)
					}
					return nil
				}}, route, nil
			}
			dependencies.closeLease = func(lease *repositorytransaction.InspectionLease) error {
				leaseCloses++
				return lease.Close()
			}
			result, err := checkWithDependencies(ctx, root, document, dependencies)
			checkWantError(t, result, err, root)
			if closes != opens || leaseCloses != 1 {
				t.Fatal("operation error skipped resource cleanup")
			}
			if strings.Contains(scenario, "close") && !errors.Is(err, repositorytransaction.ErrReadCleanup) {
				t.Fatal("file cleanup failure was not retained")
			}
			if scenario == "read and close" && !strings.Contains(err.Error(), "read selected file") {
				t.Fatal("cleanup failure masked the read failure")
			}
			if scenario == "cancel and close" && !errors.Is(err, context.Canceled) {
				t.Fatal("cleanup failure masked cancellation")
			}
			checkUnchanged(t, root, before)
		})
	}
}

func TestCheckRouteWitnessRejectsZeroInEveryState(t *testing.T) {
	for _, state := range []string{"missing", "current", "stale", "invalid"} {
		t.Run(state, func(t *testing.T) {
			root := t.TempDir()
			document := checkTestDocument(t, "codex")
			checkStateFixture(t, root, document, state)
			dependencies := nativeCheckDependencies()
			dependencies.openFile = func(lease *repositorytransaction.InspectionLease, path string) (repositorytransaction.InspectionFile, rootpath.RouteObservation, error) {
				file, _, err := lease.OpenObservedExactRegularFile(path)
				return file, rootpath.RouteObservation{}, err
			}
			before := checkTree(t, root)
			result, err := checkWithDependencies(context.Background(), root, document, dependencies)
			checkWantError(t, result, err, root)
			checkUnchanged(t, root, before)
		})
	}
}

func TestCheckRouteWitnessIgnoresUnrelatedSiblingWrites(t *testing.T) {
	for _, tool := range []string{"codex", "claude"} {
		for _, state := range []string{"missing", "current", "stale", "invalid"} {
			t.Run(tool+"/"+state, func(t *testing.T) {
				root := t.TempDir()
				document := checkTestDocument(t, tool)
				parent := filepath.Dir(filepath.Join(root, document.path))
				checkMkdir(t, parent)
				checkStateFixture(t, root, document, state)
				dependencies := nativeCheckDependencies()
				opens := 0
				var expectedTree map[string]checkTestEntry
				dependencies.openFile = func(lease *repositorytransaction.InspectionLease, path string) (repositorytransaction.InspectionFile, rootpath.RouteObservation, error) {
					opens++
					if opens == 2 {
						for directory := parent; ; directory = filepath.Dir(directory) {
							before, err := os.Stat(directory)
							if err != nil {
								t.Fatal(err)
							}
							checkWrite(t, filepath.Join(directory, "unrelated-sibling"), checkPrivateSentinel)
							changedTime := before.ModTime().Add(time.Hour)
							if err := os.Chtimes(directory, changedTime, changedTime); err != nil {
								t.Fatal(err)
							}
							if directory == root {
								break
							}
						}
						expectedTree = checkTree(t, root)
					}
					return lease.OpenObservedExactRegularFile(path)
				}
				result, err := checkWithDependencies(context.Background(), root, document, dependencies)
				checkNoDisclosure(t, result, err, root)
				if err != nil || result.State() != state || opens != 2 {
					t.Fatal("unrelated directory changes altered classification")
				}
				checkUnchanged(t, root, expectedTree)
			})
		}
	}
}
