package publicapi

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

type tsBoundaryCase struct {
	ID, Source, SourceSHA256 string
	Runtime, Types           []string
	Unsupported              bool
}

func tsBoundaryCases(t *testing.T) []tsBoundaryCase {
	t.Helper()
	data, err := os.ReadFile("testdata/typescript_boundaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Cases []tsBoundaryCase }
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("empty compiler-qualified corpus")
	}
	for _, c := range corpus.Cases {
		if fmt.Sprintf("%x", sha256.Sum256([]byte(c.Source))) != c.SourceSHA256 {
			t.Fatalf("source drift for %s", c.ID)
		}
	}
	return corpus.Cases
}

func TestCollectExportsCompilerQualifiedBoundaries(t *testing.T) {
	for _, c := range tsBoundaryCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			runtime, types, err := CollectExports(c.Source)
			if c.Unsupported {
				if err == nil {
					t.Fatal("existing unsupported production admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertStringSlice(t, runtime, c.Runtime)
			assertStringSlice(t, types, c.Types)
		})
	}
}

func TestVerifyTypeScriptCompilerQualifiedBoundaries(t *testing.T) {
	root := writeTypeScriptPackageFixture(t)
	for _, c := range tsBoundaryCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(root, "packages/alpha/src/index.ts"), []byte(c.Source), 0600); err != nil {
				t.Fatal(err)
			}
			input := publicAPIManifest()
			entry := input["entries"].([]any)[0].(map[string]any)
			set := func(runtime, types []string) {
				entry["runtimeExports"] = tsNames(runtime)
				entry["typeExports"] = tsNames(types)
			}
			set(c.Runtime, c.Types)
			report, code, err := Verify(input, Options{RepoRoot: root})
			if c.Unsupported {
				if err == nil || code != 1 || report != nil {
					t.Fatal("unsupported grammar reached manifest comparison")
				}
				return
			}
			if err != nil || code != 0 {
				t.Fatalf("exact manifest: code=%d err=%v", code, err)
			}
			checkMismatch := func() {
				t.Helper()
				report, code, err := Verify(input, Options{RepoRoot: root})
				if err != nil || code != 1 || len(report["failures"].([]any)) == 0 {
					t.Fatal("manifest mutation did not produce a failed report")
				}
			}
			set(append(append([]string{}, c.Runtime...), "zzUnexpected"), c.Types)
			checkMismatch()
			if strings.Contains(c.Source, "hidden") && !slices.Contains(c.Runtime, "hidden") {
				set(append(append([]string{}, c.Runtime...), "hidden"), c.Types)
				checkMismatch()
			}
			if len(c.Runtime) > 0 {
				set(c.Runtime[1:], c.Types)
				checkMismatch()
				set(c.Runtime[1:], append(append([]string{}, c.Types...), c.Runtime[0]))
				checkMismatch()
			} else if len(c.Types) > 0 {
				set(c.Runtime, c.Types[1:])
				checkMismatch()
				set(append(append([]string{}, c.Runtime...), c.Types[0]), c.Types[1:])
				checkMismatch()
			}
		})
	}
}

func tsNames(names []string) []any {
	ordered := append([]string{}, names...)
	sort.Strings(ordered)
	values := make([]any, len(ordered))
	for i, name := range ordered {
		values[i] = name
	}
	return values
}

func TestTypeScriptTokensOwnTriviaAndMaximalMunch(t *testing.T) {
	for _, lt := range []string{"\n", "\r", "\r\n", "\u2028", "\u2029"} {
		for _, trivia := range []string{lt, "/*" + lt + "*/", "//comment" + lt, "/*" + lt + "*/ /*plain*/ "} {
			s := tsTokens{source: "a" + trivia + "b"}
			if s.take().lineBefore || !s.take().lineBefore || s.take().kind != tsEnd || s.err != nil {
				t.Fatal("line terminator trivia was lost")
			}
		}
	}
	for _, source := range []string{"'a\\\nb' c", "`a\nb` c", "'\\\r\nb' c"} {
		s := tsTokens{source: source}
		s.take()
		if s.take().lineBefore || s.err != nil {
			t.Fatal("literal-internal newline escaped its token")
		}
	}
	s := tsTokens{source: "=> === !== ++ -- **= &&= ||= ??= ?. ... .1 1e+2 0xff 2n"}
	for _, want := range []string{"=>", "===", "!==", "++", "--", "**=", "&&=", "||=", "??=", "?.", "...", ".1", "1e+2", "0xff", "2n"} {
		if got := s.text(s.take()); got != want {
			t.Fatalf("token=%q want=%q", got, want)
		}
	}
	if s.take().kind != tsEnd || s.err != nil {
		t.Fatal("token stream did not terminate")
	}
	s = tsTokens{source: "true?.1:2"}
	for _, want := range []string{"true", "?", ".1", ":", "2"} {
		if s.text(s.take()) != want {
			t.Fatal("decimal point became optional chaining")
		}
	}
}

func TestCollectExportsRejectsLateLexicalErrorsWithoutPartialInventory(t *testing.T) {
	for _, suffix := range []string{"/*", "([)]", "const x=`${1}`", "const x=1/2", "const \\u0061=1"} {
		runtime, types, err := CollectExports("export const a=1; " + suffix)
		if err == nil || runtime != nil || types != nil {
			t.Fatal("late lexical failure exposed a partial inventory")
		}
	}
	if _, _, err := CollectExports("function privateBody(){const bad=;} export const a=1;"); err != nil {
		t.Fatal("opaque body was promoted to syntax validation")
	}
}

func TestTypeScriptTokensProgressAndDeepOpaqueRegions(t *testing.T) {
	const depth = 100000
	source := "export const a=" + strings.Repeat("(", depth) + "1" + strings.Repeat(")", depth) + ",b=2;"
	runtime, types, err := CollectExports(source)
	if err != nil {
		t.Fatal(err)
	}
	assertStringSlice(t, runtime, []string{"a", "b"})
	assertStringSlice(t, types, nil)
	s := tsTokens{source: source}
	for s.peek(0).kind != tsEnd && s.err == nil {
		token := s.take()
		if token.end <= token.start {
			t.Fatal("nonterminal token made no byte progress")
		}
	}
	if s.err != nil || s.pos != len(source) || len(s.stack) != 0 {
		t.Fatal("stream did not consume the complete source")
	}
}

func TestTypeScriptClassHeritageProgressWithinSourceDomain(t *testing.T) {
	prefix, nested, last, body, tail := "export const C=", "class extends ", "class {}", " {}", ",b=2;"
	depth := (maxSourceFileBytes - len(prefix) - len(last) - len(tail)) / (len(nested) + len(body))
	source := prefix + strings.Repeat(nested, depth) + last + strings.Repeat(body, depth) + tail
	source += strings.Repeat(" ", maxSourceFileBytes-len(source))
	if len(source) != maxSourceFileBytes {
		t.Fatal("class-chain stress must cover the existing source domain")
	}
	runtime, types, err := CollectExports(source)
	if err != nil {
		t.Fatal(err)
	}
	assertStringSlice(t, runtime, []string{"C", "b"})
	assertStringSlice(t, types, nil)
}

func TestTypeScriptAssignmentFramesProgress(t *testing.T) {
	const depth = 10000
	for _, parts := range [][3]string{
		{"x=>", "{}", ""},
		{"c?", "1", ":1"},
		{"c?(x):T=>", "1", ":1"},
		{"c?(x):T=>", "1", ""},
	} {
		source := "const c=true,x=1; type T=any; export const f=" + strings.Repeat(parts[0], depth) + parts[1] + strings.Repeat(parts[2], depth) + ",b=2;"
		runtime, types, err := CollectExports(source)
		if err != nil {
			t.Fatal(err)
		}
		assertStringSlice(t, runtime, []string{"b", "f"})
		assertStringSlice(t, types, nil)
		runtime, types, err = CollectExports(source + " const bad=1/2;")
		if err == nil || runtime != nil || types != nil {
			t.Fatal("replay exposed inventory before late lexical failure")
		}
	}
}

func TestVerifyTypeScriptReportProjectionNondisclosure(t *testing.T) {
	t.Run("long-ordinary-diagnostic", func(t *testing.T) {
		root := writeTypeScriptPackageFixture(t)
		name := strings.Repeat("ordinary_", 512)
		if _, err := nonEmptyString(name, "ordinary observation"); err != nil {
			t.Fatal("ordinary fixture was not admitted")
		}
		sourcePath := filepath.Join(root, "packages/alpha/src/index.ts")
		data, err := os.ReadFile(sourcePath)
		if err != nil {
			t.Fatal("cannot read fixture")
		}
		if os.WriteFile(sourcePath, append(data, []byte("\nexport const "+name+"=1;")...), 0600) != nil {
			t.Fatal("cannot write fixture")
		}
		report, code, err := Verify(publicAPIManifest(), Options{RepoRoot: root})
		if err != nil || code != 1 {
			t.Fatal("ordinary mismatch lost its failed report")
		}
		failures := report["failures"].([]any)
		if len(failures) != 1 || failures[0] != "@example/alpha:. runtime exports drift: missing=[] extra=["+name+"]" {
			t.Fatal("long ordinary diagnostic was truncated or changed")
		}
	})
	t.Run("sort-after-redaction", func(t *testing.T) {
		root := writeTypeScriptPackageFixture(t)
		name := "ghp_" + strings.Repeat("a", 36)
		sourcePath := filepath.Join(root, "packages/alpha/src/index.ts")
		data, err := os.ReadFile(sourcePath)
		if err != nil {
			t.Fatal("cannot read fixture")
		}
		if os.WriteFile(sourcePath, append(data, []byte("\nexport const "+name+"=1;")...), 0600) != nil {
			t.Fatal("cannot write fixture")
		}
		packagePath := filepath.Join(root, "packages/alpha/package.json")
		data, err = os.ReadFile(packagePath)
		if err != nil {
			t.Fatal("cannot read fixture")
		}
		var pkg map[string]any
		if json.Unmarshal(data, &pkg) != nil {
			t.Fatal("cannot decode fixture")
		}
		pkg["exports"].(map[string]any)["."].(map[string]any)["unexpectedCondition"] = "./src/index.ts"
		writeJSON(t, packagePath, pkg)
		report, code, err := Verify(publicAPIManifest(), Options{RepoRoot: root})
		if err != nil || code != 1 {
			t.Fatal("observation mismatch did not fail")
		}
		failures := report["failures"].([]any)
		if len(failures) != 2 || failures[0] != "<redacted-diagnostic-value>" || failures[1] != "@example/alpha exports[.] conditions drift: missing=[] extra=[unexpectedCondition]" {
			t.Fatal("failure projection must redact before canonical sorting")
		}
	})
	for _, field := range []string{"source-symbol", "package-export-key", "condition-key"} {
		for _, protected := range []bool{false, true} {
			label := field + "/ordinary"
			name := "unexpectedName"
			if protected {
				label = field + "/protected"
				name = "ghp_" + strings.Repeat("a", 36)
			}
			t.Run(label, func(t *testing.T) {
				if protected {
					if _, err := nonEmptyString(name, "synthetic observation"); err == nil {
						t.Fatal("fixture did not activate existing shared admission")
					}
				}
				root := writeTypeScriptPackageFixture(t)
				input := publicAPIManifest()
				if field == "source-symbol" {
					p := filepath.Join(root, "packages/alpha/src/index.ts")
					data, err := os.ReadFile(p)
					if err != nil {
						t.Fatal("cannot read fixture")
					}
					if err := os.WriteFile(p, append(data, []byte("\nexport const "+name+"=1;")...), 0600); err != nil {
						t.Fatal("cannot update fixture")
					}
				} else {
					p := filepath.Join(root, "packages/alpha/package.json")
					data, err := os.ReadFile(p)
					if err != nil {
						t.Fatal("cannot read fixture")
					}
					var pkg map[string]any
					if json.Unmarshal(data, &pkg) != nil {
						t.Fatal("cannot decode fixture")
					}
					exports := pkg["exports"].(map[string]any)
					if field == "package-export-key" {
						exports[name] = nil
					} else {
						exports["."].(map[string]any)[name] = "./src/index.ts"
					}
					writeJSON(t, p, pkg)
				}
				report, code, err := Verify(input, Options{RepoRoot: root})
				if err != nil || code != 1 {
					t.Fatal("observation mismatch lost its failed report")
				}
				wire, err := json.Marshal(report)
				if err != nil {
					t.Fatal("cannot encode report")
				}
				if protected {
					if strings.Contains(string(wire), name) || !strings.Contains(string(wire), "redacted-diagnostic-value") {
						t.Fatal("protected observation crossed the final report boundary")
					}
				} else if !strings.Contains(string(wire), name) {
					t.Fatal("ordinary diagnostic was suppressed")
				}
				failures := report["failures"].([]any)
				if len(failures) != 1 {
					t.Fatal("failure cardinality changed")
				}
				if !protected {
					labels := map[string]string{"source-symbol": "@example/alpha:. runtime exports", "package-export-key": "@example/alpha package.json export keys", "condition-key": "@example/alpha exports[.] conditions"}
					if failures[0] != labels[field]+" drift: missing=[] extra=[unexpectedName]" {
						t.Fatal("ordinary diagnostic bytes changed")
					}
				}
			})
		}
	}
}
