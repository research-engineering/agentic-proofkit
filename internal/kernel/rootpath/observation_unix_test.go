//go:build darwin || linux

package rootpath

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func observedRoute(t *testing.T, root *os.Root, path string, wantErr error) RouteObservation {
	t.Helper()
	file, observation, err := OpenObservedExactRegularFile(root, path)
	if !errors.Is(err, wantErr) {
		t.Fatalf("observed open error=%v, want %v", err, wantErr)
	}
	if file != nil {
		if wantErr != nil {
			t.Fatal("non-regular outcome returned a file")
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return observation
}

func TestObservedOpenPreservesLegacyResultsAndPrivateWitness(t *testing.T) {
	for _, state := range []string{"regular", "missing parent", "missing leaf", "unsafe parent", "directory", "symlink", "FIFO"} {
		t.Run(state, func(t *testing.T) {
			rootPath := t.TempDir()
			parent := filepath.Join(rootPath, "docs")
			selected := filepath.Join(parent, "record")
			wantErr := error(nil)
			if state != "missing parent" && state != "unsafe parent" {
				if err := os.Mkdir(parent, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			switch state {
			case "regular":
				if err := os.WriteFile(selected, []byte("private witness fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing parent", "missing leaf":
				wantErr = fs.ErrNotExist
			case "unsafe parent":
				wantErr = ErrUnsafeRoute
				if err := os.WriteFile(parent, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				wantErr = ErrUnsafeRoute
				if err := os.Mkdir(selected, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				wantErr = ErrUnsafeRoute
				if err := os.Symlink("private-link-target", selected); err != nil {
					t.Fatal(err)
				}
			case "FIFO":
				wantErr = ErrUnsafeRoute
				if err := unix.Mkfifo(selected, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := os.OpenRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			before := observedRoute(t, root, "docs/record", wantErr)
			after := observedRoute(t, root, "docs/record", wantErr)
			if !before.Equal(after) || !after.Equal(before) {
				t.Fatal("stable route observations differ")
			}
			position, terminal, count := 1, routeRegular, 3
			switch state {
			case "missing parent":
				position, terminal, count = 0, routeMissing, 1
			case "missing leaf":
				terminal, count = routeMissing, 2
			case "unsafe parent":
				position, terminal, count = 0, routeUnsafe, 2
			case "directory", "symlink", "FIFO":
				terminal = routeUnsafe
			}
			if before.position != position || before.terminal != terminal || len(before.components) != count {
				t.Fatal("witness did not retain the observed terminal and component count")
			}
			for index, path := range []string{rootPath, parent, selected}[:count] {
				var stat unix.Stat_t
				if err := unix.Lstat(path, &stat); err != nil {
					t.Fatal(err)
				}
				component := before.components[index]
				if component.device != uint64(stat.Dev) || component.inode != uint64(stat.Ino) || component.mode != uint32(stat.Mode) {
					t.Fatal("witness disagrees with independent native component metadata")
				}
			}
			file, err := OpenExactRegularFile(root, "docs/record")
			if !errors.Is(err, wantErr) {
				t.Fatalf("legacy open error=%v, want %v", err, wantErr)
			}
			if file != nil {
				content, err := io.ReadAll(file)
				closeErr := file.Close()
				if err != nil || closeErr != nil || string(content) != "private witness fixture" {
					t.Fatal("legacy content or cleanup changed")
				}
			}
			// A public envelope must neither disclose nor re-admit its opaque child.
			type observationEnvelope struct {
				Route RouteObservation `json:"route"`
			}
			encoded, err := json.Marshal(observationEnvelope{Route: before})
			if err != nil || string(encoded) != `{"route":{}}` {
				t.Fatal("route witness exposed wire data")
			}
			var decoded observationEnvelope
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.Route.Equal(before) || decoded.Route.Equal(decoded.Route) {
				t.Fatal("wire roundtrip admitted a witness")
			}
		})
	}
}

func TestRouteObservationEqualityBindsEveryOperand(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootPath, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "docs/record"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	before := observedRoute(t, root, "docs/record", nil)
	mutations := map[string]func(*RouteObservation){
		"route":       func(value *RouteObservation) { value.route = "other/record" },
		"terminal":    func(value *RouteObservation) { value.terminal = routeUnsafe },
		"position":    func(value *RouteObservation) { value.position-- },
		"incomplete":  func(value *RouteObservation) { value.terminal = routeIncomplete },
		"truncated":   func(value *RouteObservation) { value.components = value.components[:1] },
		"empty route": func(value *RouteObservation) { value.route = "" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			after := before
			mutate(&after)
			if before.Equal(after) || after.Equal(before) {
				t.Fatal("changed witness operand compared equal")
			}
		})
	}
	// Isolate each equality operand from the other fields of real observations;
	// device-only differences need no host-specific second mounted filesystem.
	for index := range before.components {
		for _, operand := range []string{"device", "inode", "type", "mode"} {
			after := before
			after.components = slices.Clone(before.components)
			switch operand {
			case "device":
				after.components[index].device++
			case "inode":
				after.components[index].inode++
			case "type":
				after.components[index].mode ^= unix.S_IFDIR
			case "mode":
				after.components[index].mode ^= 0o100
			}
			if before.Equal(after) || after.Equal(before) {
				t.Fatalf("component %d operand %s was ignored", index, operand)
			}
		}
	}
	for _, invalid := range []RouteObservation{{}, {route: "record", terminal: routeRegular}, {route: "record", terminal: routeMissing, position: 2}} {
		if invalid.Equal(invalid) || before.Equal(invalid) || invalid.Equal(before) {
			t.Fatal("incomplete witness was admitted")
		}
	}
	if !before.Equal(observedRoute(t, root, "docs/record", nil)) {
		t.Fatal("comparison changed immutable observation")
	}
}

func TestObservedOpenBindsRealRouteChangesWithoutSiblingMetadata(t *testing.T) {
	rootPath := t.TempDir()
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	before := observedRoute(t, root, "docs/record", fs.ErrNotExist)
	parent := filepath.Join(rootPath, "docs")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	after := observedRoute(t, root, "docs/record", fs.ErrNotExist)
	if before.Equal(after) {
		t.Fatal("missing terminal position was ignored")
	}
	if err := os.WriteFile(filepath.Join(parent, "record"), []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	before = observedRoute(t, root, "docs/record", nil)
	if err := os.Link(filepath.Join(parent, "record"), filepath.Join(parent, "alias")); err != nil {
		t.Fatal(err)
	}
	if before.Equal(observedRoute(t, root, "docs/alias", nil)) {
		t.Fatal("hardlink path key was ignored")
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	changedTime := info.ModTime().Add(time.Hour)
	if err := os.Chtimes(parent, changedTime, changedTime); err != nil {
		t.Fatal(err)
	}
	if !before.Equal(observedRoute(t, root, "docs/record", nil)) {
		t.Fatal("sibling write or parent timestamp changed witness")
	}
	if err := os.Rename(parent, parent+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(parent+".saved", "record"), filepath.Join(parent, "record")); err != nil {
		t.Fatal(err)
	}
	if before.Equal(observedRoute(t, root, "docs/record", nil)) {
		t.Fatal("parent replacement preserved witness")
	}
}

func TestObservedOpenRejectsAdmissionModeDriftAndCleanup(t *testing.T) {
	for _, scenario := range []string{"parent mode", "leaf mode", "missing cleanup", "unsafe cleanup", "regular cleanup", "alias"} {
		t.Run(scenario, func(t *testing.T) {
			rootPath := t.TempDir()
			parent := filepath.Join(rootPath, "docs")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			selected := filepath.Join(parent, "record")
			switch scenario {
			case "missing cleanup":
			case "unsafe cleanup":
				if err := os.Mkdir(selected, 0o700); err != nil {
					t.Fatal(err)
				}
			case "alias":
				if err := os.WriteFile(filepath.Join(parent, "RECORD"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(selected, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := os.OpenRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			operations := nativeTraversalOperations()
			wantErr := ErrRouteChanged
			if scenario == "missing cleanup" || scenario == "unsafe cleanup" || scenario == "regular cleanup" {
				wantErr = ErrTraversalCleanup
				operations.closeFile = func(file *os.File) error {
					err := file.Close()
					if file.Name() == "exact-root-entry" {
						return errors.Join(err, errors.New("injected cleanup failure"))
					}
					return err
				}
			}
			if scenario == "alias" {
				wantErr = ErrAmbiguousRoute
			}
			file, observation, err := openObservedExactRegularFileWithOperations(root, "docs/record", func(index int) {
				if scenario == "parent mode" && index == 0 {
					if err := os.Chmod(parent, 0o500); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
				}
				if scenario == "leaf mode" && index == 1 {
					if err := os.Chmod(selected, 0o400); err != nil {
						t.Fatal(err)
					}
				}
			}, operations)
			if file != nil {
				_ = file.Close()
				t.Fatal("failed admission returned a file")
			}
			if !errors.Is(err, wantErr) || observation.Equal(observation) {
				t.Fatalf("error=%v, want %v and no complete witness", err, wantErr)
			}
		})
	}
}
