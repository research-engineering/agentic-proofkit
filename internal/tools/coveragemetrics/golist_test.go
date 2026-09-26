package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func goListFixture(t testing.TB) (string, bindingFile) {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.invalid/witness\n\ngo 1.25.0\n",
		"a/a.go": "package a\n",
		"a/internal_test.go": `package a
import "testing"
func TestInternal(t *testing.T) { checkInternal(t) }
func checkInternal(t *testing.T) { if 1 != 1 { t.Fatal("internal") } }
`,
		"a/external_test.go": `package a_test
import "testing"
func TestExternal(t *testing.T) { checkExternal(t) }
func checkExternal(t *testing.T) { if 1 != 1 { t.Fatal("external") } }
`,
		"a/inactive_test.go": `//go:build proofkit_never

package a
import "testing"
func TestInactive(t *testing.T) { t.Fatal("inactive") }
`,
		"b/b_test.go": `package b
import "testing"
func TestB(t *testing.T) { if 1 != 1 { t.Fatal("b") } }
`,
	}
	for path, source := range files {
		absolute := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, bindingFile{Bindings: []bindingScenario{
		bindingSelectorFixture("internal", "a/internal_test.go", "TestInternal"),
		bindingSelectorFixture("b", "b/b_test.go", "TestB"),
		bindingSelectorFixture("external", "a/external_test.go", "TestExternal"),
	}}
}

func TestBindingWitnessGoListInvocationCount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native counting wrapper requires a POSIX shell")
	}
	root, bindings := goListFixture(t)
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	logPath := filepath.Join(bin, "calls")
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	script := "#!/bin/sh\nprintf 'call\\n' >> " + quote(logPath) + "\nexec " + quote(goPath) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := validateBindingWitnessSelectorExecutabilityAtRoot(root, bindings); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(calls), "call\n"); got != 1 {
		t.Fatalf("native go list invocations=%d, want 1 for two distinct packages and three bindings", got)
	}
}

func goListJSON(t testing.TB, packages ...goWitnessPackage) []byte {
	t.Helper()
	var output []byte
	for _, listed := range packages {
		encoded, err := json.Marshal(listed)
		if err != nil {
			t.Fatal(err)
		}
		output = append(output, encoded...)
		output = append(output, '\n')
	}
	return output
}

func goListRecords(root string) (goWitnessPackage, goWitnessPackage) {
	return goWitnessPackage{
		Dir: filepath.Join(root, "a"), Match: []string{"./a"},
		TestGoFiles: []string{"internal_test.go"}, XTestGoFiles: []string{"external_test.go"},
	}, goWitnessPackage{
		Dir: filepath.Join(root, "b"), Match: []string{"./b"}, TestGoFiles: []string{"b_test.go"},
	}
}

func TestGoWitnessListStreamMapping(t *testing.T) {
	root := t.TempDir()
	a, b := goListRecords(root)
	shared := a
	shared.Match = []string{"./a", "example.invalid/witness/a"}
	duplicate := a
	duplicate.Match = []string{"./a", "./a"}
	extra := b
	extra.Match = []string{"./extra"}
	mixed := a
	mixed.Match = []string{"./a", "./extra"}
	for _, test := range []struct {
		name      string
		selectors []string
		output    []byte
		want      map[string]goWitnessPackage
	}{
		{"reverse order", []string{"./a", "./b"}, goListJSON(t, b, a), map[string]goWitnessPackage{"./a": a, "./b": b}},
		{"shared object", shared.Match, goListJSON(t, shared), map[string]goWitnessPackage{"./a": shared, "example.invalid/witness/a": shared}},
		{"trailing whitespace", []string{"./a", "./b"}, append(goListJSON(t, a, b), []byte(" \n\t ")...), map[string]goWitnessPackage{"./a": a, "./b": b}},
		{"duplicate object", []string{"./a", "./b"}, goListJSON(t, a, b, a), nil},
		{"duplicate within object", []string{"./a", "./b"}, goListJSON(t, duplicate, b), nil},
		{"missing selector", []string{"./a", "./b"}, goListJSON(t, a), nil},
		{"unknown object", []string{"./a", "./b"}, goListJSON(t, a, b, extra), nil},
		{"unknown match", []string{"./a", "./b"}, goListJSON(t, mixed, b), nil},
		{"no Match", []string{"./a"}, []byte(`{"Dir":"/a"}`), nil},
		{"empty", []string{"./a"}, nil, nil},
		{"whitespace only", []string{"./a"}, []byte(" \n\t"), nil},
		{"null", []string{"./a"}, []byte("null"), nil},
		{"array", []string{"./a"}, []byte("[]"), nil},
		{"malformed", []string{"./a"}, []byte("provider-private"), nil},
		{"truncated second", []string{"./a", "./b"}, append(goListJSON(t, a), []byte(`{"Match":["./b"]`)...), nil},
		{"trailing garbage", []string{"./a", "./b"}, append(goListJSON(t, a, b), []byte("provider-private")...), nil},
		{"trailing null", []string{"./a", "./b"}, append(goListJSON(t, a, b), []byte("null")...), nil},
		{"wrong field type", []string{"./a"}, []byte(`{"Match":["./a"],"TestGoFiles":42}`), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			got, err := listGoWitnessPackages(root, test.selectors, func(dir string, args ...string) ([]byte, error) {
				calls++
				want := append([]string{"list", "-e", "-json=Dir,Match,TestGoFiles,XTestGoFiles,Error,DepsErrors,Incomplete"}, test.selectors...)
				if dir != root || !reflect.DeepEqual(args, want) {
					t.Fatalf("go list dir=%q args=%v, want dir=%q args=%v", dir, args, root, want)
				}
				return test.output, nil
			})
			if calls != 1 || (err == nil) != (test.want != nil) || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("calls=%d result=%v error=%v, want result=%v", calls, got, err, test.want)
			}
			if err != nil && strings.Contains(err.Error(), "provider-private") {
				t.Fatal("native output echoed in diagnostic")
			}
		})
	}
}

func TestGoWitnessListPackageErrorsRemainNonEvidence(t *testing.T) {
	for _, field := range []string{`"Error":{"Err":"provider-private"}`, `"DepsErrors":[{"Err":"provider-private"}]`, `"Incomplete":true`} {
		t.Run(strings.SplitN(field, ":", 2)[0], func(t *testing.T) {
			output := []byte(`{"Dir":"/a","Match":["./a"],"TestGoFiles":["internal_test.go"],` + field + `}`)
			got, err := listGoWitnessPackages("unused", []string{"./a"}, func(string, ...string) ([]byte, error) { return output, nil })
			if err != nil || len(got) != 1 {
				t.Fatalf("package error was not retained for the binding check: %v", err)
			}
			files, err := activeGoTestFiles("./a", got["./a"])
			if files != nil || err == nil || strings.Contains(err.Error(), "provider-private") {
				t.Fatalf("package error admitted or echoed: files=%v error=%v", files, err)
			}
		})
	}
}

func TestGoWitnessListLaunchFailureAndSplitting(t *testing.T) {
	root := t.TempDir()
	a, b := goListRecords(root)
	tooBig := &os.PathError{Op: "fork/exec", Path: "provider-private", Err: syscall.E2BIG}
	for _, test := range []struct {
		name      string
		firstErr  error
		left      string
		right     string
		wantCalls [][]string
		wantOK    bool
	}{
		{"launch E2BIG", tooBig, "ok", "ok", [][]string{{"./a", "./b"}, {"./a"}, {"./b"}}, true},
		{"wrapped launch E2BIG", fmt.Errorf("launch: %w", tooBig), "ok", "ok", [][]string{{"./a", "./b"}, {"./a"}, {"./b"}}, true},
		{"single selector E2BIG", tooBig, "too big", "ok", [][]string{{"./a", "./b"}, {"./a"}}, false},
		{"later child failure", tooBig, "ok", "failed", [][]string{{"./a", "./b"}, {"./a"}, {"./b"}}, false},
		{"later child invalid stream", tooBig, "ok", "malformed", [][]string{{"./a", "./b"}, {"./a"}, {"./b"}}, false},
		{"cross chunk match", tooBig, "wrong match", "ok", [][]string{{"./a", "./b"}, {"./a"}}, false},
		{"ordinary error", errors.New("provider-private"), "ok", "ok", [][]string{{"./a", "./b"}}, false},
		{"nonzero exit", &exec.ExitError{Stderr: []byte("provider-private")}, "ok", "ok", [][]string{{"./a", "./b"}}, false},
		{"bare E2BIG", syscall.E2BIG, "ok", "ok", [][]string{{"./a", "./b"}}, false},
		{"nonlaunch E2BIG", &os.PathError{Op: "read", Err: syscall.E2BIG}, "ok", "ok", [][]string{{"./a", "./b"}}, false},
		{"launch permission error", &os.PathError{Op: "fork/exec", Err: syscall.EACCES}, "ok", "ok", [][]string{{"./a", "./b"}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls [][]string
			got, err := listGoWitnessPackages(root, []string{"./a", "./b"}, func(_ string, args ...string) ([]byte, error) {
				selectors := args[3:]
				calls = append(calls, append([]string(nil), selectors...))
				if len(selectors) == 2 {
					return goListJSON(t, a, b), test.firstErr
				}
				mode, listed := test.left, a
				if selectors[0] == "./b" {
					mode, listed = test.right, b
				}
				switch mode {
				case "too big":
					return nil, tooBig
				case "failed":
					return goListJSON(t, listed), errors.New("provider-private")
				case "malformed":
					return append(goListJSON(t, listed), []byte("provider-private")...), nil
				case "wrong match":
					return goListJSON(t, b), nil
				default:
					return goListJSON(t, listed), nil
				}
			})
			if !reflect.DeepEqual(calls, test.wantCalls) || (err == nil) != test.wantOK {
				t.Fatalf("calls=%v error=%v, want calls=%v success=%v", calls, err, test.wantCalls, test.wantOK)
			}
			if test.wantOK {
				if !reflect.DeepEqual(got, map[string]goWitnessPackage{"./a": a, "./b": b}) {
					t.Fatalf("incomplete split result: %v", got)
				}
			} else if got != nil || strings.Contains(err.Error(), "provider-private") {
				t.Fatalf("partial stdout admitted or native error echoed: result=%v error=%v", got, err)
			}
		})
	}
}

func TestBindingWitnessGoListOrdering(t *testing.T) {
	for _, test := range []struct {
		name      string
		mutate    func(*testing.T, string, *bindingFile, *goWitnessPackage, *goWitnessPackage)
		want      string
		wantCalls int
	}{
		{"distinct first occurrence order", func(_ *testing.T, _ string, bindings *bindingFile, _, _ *goWitnessPackage) {
			bindings.Bindings = append([]bindingScenario{bindings.Bindings[1]}, bindings.Bindings...)
		}, "", 1},
		{"no selectors", func(_ *testing.T, _ string, bindings *bindingFile, _, _ *goWitnessPackage) {
			for index := range bindings.Bindings {
				bindings.Bindings[index].WitnessSelectors = nil
			}
		}, "", 0},
		{"late command before first source", func(t *testing.T, root string, bindings *bindingFile, _, _ *goWitnessPackage) {
			if err := os.Remove(filepath.Join(root, bindings.Bindings[0].WitnessPath)); err != nil {
				t.Fatal(err)
			}
			bindings.Bindings[2].WitnessSelectors[0].Command = "wrong"
		}, "binding external selector command=", 0},
		{"first source before list", func(t *testing.T, root string, bindings *bindingFile, _, _ *goWitnessPackage) {
			if err := os.Remove(filepath.Join(root, bindings.Bindings[0].WitnessPath)); err != nil {
				t.Fatal(err)
			}
		}, "parse binding witness a/internal_test.go:", 0},
		{"first selector before list", func(_ *testing.T, _ string, bindings *bindingFile, _, _ *goWitnessPackage) {
			bindings.Bindings[0] = bindingSelectorFixture("missing", "a/internal_test.go", "TestMissing")
		}, "binding missing selector TestMissing is missing", 0},
		{"invalid signature before list", func(t *testing.T, root string, _ *bindingFile, _, _ *goWitnessPackage) {
			if err := os.WriteFile(filepath.Join(root, "a/internal_test.go"), []byte("package a\nfunc TestInternal() {}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "is not a valid Go test function", 0},
		{"first inactive before later error", func(_ *testing.T, _ string, _ *bindingFile, a, b *goWitnessPackage) {
			a.TestGoFiles = nil
			b.Error = &struct{}{}
		}, "binding internal witness a/internal_test.go is not active", 1},
		{"first skip before later error", func(t *testing.T, root string, _ *bindingFile, _, b *goWitnessPackage) {
			if err := os.WriteFile(filepath.Join(root, "a/internal_test.go"), []byte("package a\nimport \"testing\"\nfunc TestInternal(t *testing.T) { t.Skip(\"skip\") }\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			b.Error = &struct{}{}
		}, "binding internal selector TestInternal contains t.Skip", 1},
		{"first oracle before later error", func(t *testing.T, root string, _ *bindingFile, _, b *goWitnessPackage) {
			if err := os.WriteFile(filepath.Join(root, "a/internal_test.go"), []byte("package a\nimport \"testing\"\nfunc TestInternal(t *testing.T) {}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			b.Error = &struct{}{}
		}, "binding internal selector TestInternal has no failure-capable assertion", 1},
		{"later source before its package error", func(t *testing.T, root string, _ *bindingFile, _, b *goWitnessPackage) {
			if err := os.Remove(filepath.Join(root, "b/b_test.go")); err != nil {
				t.Fatal(err)
			}
			b.Error = &struct{}{}
		}, "parse binding witness b/b_test.go:", 1},
		{"later selector before its package error", func(_ *testing.T, _ string, bindings *bindingFile, _, b *goWitnessPackage) {
			bindings.Bindings[1] = bindingSelectorFixture("missing", "b/b_test.go", "TestMissing")
			b.Error = &struct{}{}
		}, "binding missing selector TestMissing is missing", 1},
		{"later error at own binding", func(_ *testing.T, _ string, _ *bindingFile, _, b *goWitnessPackage) {
			b.Error = &struct{}{}
		}, "discover binding witness b/b_test.go: go list ./b: package or dependency has errors", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, bindings := goListFixture(t)
			a, b := goListRecords(root)
			test.mutate(t, root, &bindings, &a, &b)
			calls := 0
			err := validateBindingWitnessSelectorExecutabilityWithGoList(root, bindings, func(dir string, args ...string) ([]byte, error) {
				calls++
				want := []string{"./a", "./b"}
				if test.name == "distinct first occurrence order" {
					want = []string{"./b", "./a"}
				}
				if dir != root || !reflect.DeepEqual(args[3:], want) {
					t.Fatalf("dir=%q selectors=%v, want dir=%q selectors=%v", dir, args[3:], root, want)
				}
				return goListJSON(t, b, a), nil
			})
			if calls != test.wantCalls || (test.want == "" && err != nil) || (test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want))) {
				t.Fatalf("calls=%d error=%v, want calls=%d error containing %q", calls, err, test.wantCalls, test.want)
			}
		})
	}
	t.Run("empty adapter input", func(t *testing.T) {
		got, err := listGoWitnessPackages("unused", nil, func(string, ...string) ([]byte, error) { t.Fatal("unexpected invocation"); return nil, nil })
		if err != nil || len(got) != 0 {
			t.Fatalf("result=%v error=%v", got, err)
		}
	})
}

func TestGoWitnessListNativeSources(t *testing.T) {
	root, bindings := goListFixture(t)
	listed, err := listGoWitnessPackages(root, []string{"./a", "example.invalid/witness/a", "./b"}, runGoWitnessList)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(listed["./a"], listed["example.invalid/witness/a"]) {
		t.Fatal("native equivalent selectors did not share one package record")
	}
	active, err := activeGoTestFiles("./a", listed["./a"])
	want := map[string]struct{}{filepath.Join(root, "a", "internal_test.go"): {}, filepath.Join(root, "a", "external_test.go"): {}}
	if err != nil || !reflect.DeepEqual(active, want) {
		t.Fatalf("active files=%v error=%v, want %v", active, err, want)
	}
	if err := validateBindingWitnessSelectorExecutabilityAtRoot(root, bindings); err != nil {
		t.Fatal(err)
	}
	inactive := bindingFile{Bindings: []bindingScenario{bindingSelectorFixture("inactive", "a/inactive_test.go", "TestInactive")}}
	if err := validateBindingWitnessSelectorExecutabilityAtRoot(root, inactive); err == nil || !strings.Contains(err.Error(), "is not active") {
		t.Fatalf("inactive witness admitted: %v", err)
	}
	for _, helper := range []string{"checkExternal", "checkInactive"} {
		t.Run(helper, func(t *testing.T) {
			root, bindings := goListFixture(t)
			source := "package a\nimport \"testing\"\nfunc TestInternal(t *testing.T) { " + helper + "(t) }\n"
			if err := os.WriteFile(filepath.Join(root, "a/internal_test.go"), []byte(source), 0o644); err != nil {
				t.Fatal(err)
			}
			if helper == "checkInactive" {
				source = "//go:build proofkit_never\n\npackage a\nimport \"testing\"\nfunc checkInactive(t *testing.T) { t.Fatal(\"inactive\") }\n"
				if err := os.WriteFile(filepath.Join(root, "a/inactive_test.go"), []byte(source), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := validateBindingWitnessSelectorExecutabilityAtRoot(root, bindings); err == nil || !strings.Contains(err.Error(), "no failure-capable assertion candidate") {
				t.Fatalf("out-of-scope helper admitted: %v", err)
			}
		})
	}
}

func TestGoWitnessListNativePackageErrors(t *testing.T) {
	for _, test := range []struct{ name, source string }{
		{"package error", "package different\n"},
		{"dependency error", "package b\nimport _ \"example.invalid/witness/missing\"\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, bindings := goListFixture(t)
			if err := os.WriteFile(filepath.Join(root, "b/b.go"), []byte(test.source), 0o644); err != nil {
				t.Fatal(err)
			}
			listed, err := listGoWitnessPackages(root, []string{"./a", "./b"}, runGoWitnessList)
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "package error" && listed["./b"].Error == nil {
				t.Fatal("native fixture did not produce Error")
			}
			if test.name == "dependency error" && len(listed["./b"].DepsErrors) == 0 {
				t.Fatal("native fixture did not produce DepsErrors")
			}
			if !listed["./b"].Incomplete {
				t.Fatal("native fixture did not produce Incomplete")
			}
			if err := validateBindingWitnessSelectorExecutabilityAtRoot(root, bindings); err == nil || err.Error() != "discover binding witness b/b_test.go: go list ./b: package or dependency has errors" {
				t.Fatalf("native package error at wrong binding: %v", err)
			}
		})
	}
}

func TestGoWitnessListNativeRootSelector(t *testing.T) {
	root, bindings := goListFixture(t)
	source := "package witness\nimport \"testing\"\nfunc TestRoot(t *testing.T) { if 1 != 1 { t.Fatal(\"root\") } }\n"
	if err := os.WriteFile(filepath.Join(root, "root_test.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	bindings.Bindings = append([]bindingScenario{
		bindingSelectorFixture("root", "root_test.go", "TestRoot"),
		bindingSelectorFixture("root-again", "./root_test.go", "TestRoot"),
	}, bindings.Bindings...)
	var calls [][]string
	err := validateBindingWitnessSelectorExecutabilityWithGoList(root, bindings, func(dir string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args[3:]...))
		return runGoWitnessList(dir, args...)
	})
	if err != nil {
		t.Fatalf("native root witness rejected: %v", err)
	}
	if !reflect.DeepEqual(calls, [][]string{{".", "./a", "./b"}}) {
		t.Fatalf("native root selectors=%v, want one canonical explicit batch", calls)
	}
}

func BenchmarkGoWitnessDiscovery(b *testing.B) {
	root := filepath.Join("..", "..", "..")
	paths := []string{"./internal/tools/coveragemetrics", "./internal/kernel/gotestsource", "./internal/command/testevidenceinventory"}
	for _, batched := range []bool{false, true} {
		name, calls := "per-package", len(paths)
		if batched {
			name, calls = "batched", 1
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(calls), "go-list/op")
			for range b.N {
				listed := map[string]goWitnessPackage{}
				if batched {
					var err error
					listed, err = listGoWitnessPackages(root, paths, runGoWitnessList)
					if err != nil {
						b.Fatal(err)
					}
				} else {
					for _, path := range paths {
						output, err := runGoWitnessList(root, "list", "-json", path)
						if err != nil {
							b.Fatal(err)
						}
						var legacy struct {
							Dir                       string
							TestGoFiles, XTestGoFiles []string
						}
						if err := json.Unmarshal(output, &legacy); err != nil {
							b.Fatal(err)
						}
						listed[path] = goWitnessPackage{Dir: legacy.Dir, TestGoFiles: legacy.TestGoFiles, XTestGoFiles: legacy.XTestGoFiles}
					}
				}
				for _, path := range paths {
					if _, err := activeGoTestFiles(path, listed[path]); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
