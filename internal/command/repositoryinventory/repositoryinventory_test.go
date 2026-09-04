package repositoryinventory

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestCatalogPathsAreSortedAndUnique(t *testing.T) {
	paths := catalogPaths()
	if !slices.IsSorted(paths) {
		t.Fatalf("catalogPaths() = %v, want sorted paths", paths)
	}
	for index := 1; index < len(paths); index++ {
		if paths[index-1] == paths[index] {
			t.Fatalf("catalogPaths() contains duplicate %q", paths[index])
		}
	}
}

func TestCatalogRolePolicyIsExact(t *testing.T) {
	want := map[string]string{
		"AGENTS.md":         "agent_instructions",
		"Cargo.lock":        "dependency_lock",
		"Cargo.toml":        "ecosystem_manifest",
		"Gemfile":           "ecosystem_manifest",
		"Gemfile.lock":      "dependency_lock",
		"README.md":         "human_overview",
		"build.gradle":      "build_configuration",
		"build.gradle.kts":  "build_configuration",
		"bun.lock":          "dependency_lock",
		"composer.json":     "ecosystem_manifest",
		"composer.lock":     "dependency_lock",
		"deno.json":         "ecosystem_manifest",
		"deno.jsonc":        "ecosystem_manifest",
		"go.mod":            "ecosystem_manifest",
		"go.sum":            "dependency_lock",
		"package-lock.json": "dependency_lock",
		"package.json":      "ecosystem_manifest",
		"pnpm-lock.yaml":    "dependency_lock",
		"poetry.lock":       "dependency_lock",
		"pom.xml":           "ecosystem_manifest",
		"pyproject.toml":    "ecosystem_manifest",
		"requirements.txt":  "dependency_declaration",
		"tsconfig.json":     "build_configuration",
		"uv.lock":           "dependency_lock",
		"yarn.lock":         "dependency_lock",
	}
	if got := catalogPaths(); len(got) != len(want) {
		t.Fatalf("catalog path count = %d, want %d", len(got), len(want))
	}
	for path, wantRole := range want {
		gotRole, ok := catalogRole(path)
		if !ok || gotRole != wantRole {
			t.Fatalf("catalogRole(%q) = %q/%t, want %q/true", path, gotRole, ok, wantRole)
		}
	}
	if role, ok := catalogRole("unknown"); ok || role != "" {
		t.Fatalf("catalogRole(unknown) = %q/%t, want empty/false", role, ok)
	}
}

func TestReadRootInventoryClassifiesPartialBatchesWithoutRetainingUnknownNames(t *testing.T) {
	root := t.TempDir()
	writeInventoryFixture(t, root, "README.md", nil)
	writeInventoryFixture(t, root, "api_key=unknown-name-sentinel", nil)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	reader := &partialDirectoryReader{batches: [][]os.DirEntry{{entries[0]}, {entries[1]}}}
	inventory, err := readRootInventory(context.Background(), reader, 2)
	if err != nil {
		t.Fatalf("readRootInventory() error = %v", err)
	}
	if inventory.rootEntryCount != 2 || inventory.unrecognizedCount != 1 ||
		!slices.Equal(inventory.catalogItems, []catalogItem{{Path: "README.md", Role: "human_overview"}}) {
		t.Fatalf("readRootInventory() = %#v, want one fixed-catalog item and one opaque count", inventory)
	}
	for _, item := range inventory.catalogItems {
		if strings.Contains(item.Path, "sentinel") {
			t.Fatalf("readRootInventory retained unknown name in %#v", inventory)
		}
	}

	reader = &partialDirectoryReader{batches: [][]os.DirEntry{{entries[0]}, {entries[1]}}}
	if _, err := readRootInventory(context.Background(), reader, 1); err == nil || !strings.Contains(err.Error(), "entry limit") {
		t.Fatalf("readRootInventory() error = %v, want entry-limit rejection", err)
	}
}

type partialDirectoryReader struct {
	batches [][]os.DirEntry
	index   int
}

func (reader *partialDirectoryReader) ReadDir(_ int) ([]os.DirEntry, error) {
	if reader.index >= len(reader.batches) {
		return nil, io.EOF
	}
	batch := reader.batches[reader.index]
	reader.index++
	return batch, nil
}

func TestScanProducesBoundedClosedInventory(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.110211556856580299924889797330865109231063384949664159872540683038190051047716")
	root := t.TempDir()
	writeInventoryFixture(t, root, "README.md", []byte("# Example\n"))
	writeInventoryFixture(t, root, "package.json", []byte("{\"name\":\"example\"}\n"))
	unknownName := "api_key=sentinel-should-not-be-disclosed"
	writeInventoryFixture(t, root, unknownName, []byte("sentinel-unknown-content"))

	snapshot, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if got, want := len(snapshot.Entries), 2; got != want {
		t.Fatalf("len(Entries) = %d, want %d", got, want)
	}
	if snapshot.Entries[0].Path != "README.md" || snapshot.Entries[1].Path != "package.json" {
		t.Fatalf("Entries = %#v, want canonical catalog order", snapshot.Entries)
	}
	if snapshot.Entries[0].ContentSHA256 != digest.SHA256BytesRef([]byte("# Example\n")) {
		t.Fatalf("README digest = %q, want content digest", snapshot.Entries[0].ContentSHA256)
	}
	if snapshot.Omissions.RootEntryCount != 3 || snapshot.Omissions.UnrecognizedCount != 1 {
		t.Fatalf("Omissions = %#v, want closed root partition", snapshot.Omissions)
	}

	encoded, err := stablejson.Marshal(snapshot.JSONValue())
	if err != nil {
		t.Fatalf("stablejson.Marshal() error = %v", err)
	}
	for _, forbidden := range []string{root, unknownName, "sentinel-unknown-content"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("inventory disclosed %q: %s", forbidden, encoded)
		}
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatalf("DecodeJSON() error = %v", err)
	}
	admitted, err := AdmitOutput(decoded)
	if err != nil {
		t.Fatalf("AdmitOutput() error = %v", err)
	}
	if admitted.InventoryID != snapshot.InventoryID {
		t.Fatalf("AdmitOutput().InventoryID = %q, want %q", admitted.InventoryID, snapshot.InventoryID)
	}
}

func TestScanRejectsRecognizedSymlinkWithoutReadingTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "secret.txt")
	writeInventoryFixture(t, filepath.Dir(target), filepath.Base(target), []byte("sentinel-target-content"))
	if err := os.Symlink(target, filepath.Join(root, "README.md")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	_, err := Scan(context.Background(), root)
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("Scan() error = %v, want recognized symlink rejection", err)
	}
	if strings.Contains(err.Error(), target) || strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("Scan() disclosed symlink target: %v", err)
	}
}

func TestScanDoesNotFollowUnknownSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "secret.txt")
	writeInventoryFixture(t, filepath.Dir(target), filepath.Base(target), []byte("sentinel-target-content"))
	if err := os.Symlink(target, filepath.Join(root, "unknown-link")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	snapshot, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(snapshot.Entries) != 0 || snapshot.Omissions.RootEntryCount != 1 || snapshot.Omissions.UnrecognizedCount != 1 {
		t.Fatalf("Scan() = %#v, want one opaque unrecognized entry", snapshot)
	}
	encoded, _ := stablejson.Marshal(snapshot.JSONValue())
	if strings.Contains(string(encoded), "unknown-link") || strings.Contains(string(encoded), "sentinel") {
		t.Fatalf("inventory disclosed unknown symlink details: %s", encoded)
	}
}

func TestScanEnforcesPreflightBoundsAndExplicitOmissions(t *testing.T) {
	t.Run("root entry limit", func(t *testing.T) {
		rootPath := t.TempDir()
		writeInventoryFixture(t, rootPath, "README.md", []byte("a"))
		writeInventoryFixture(t, rootPath, "unknown", []byte("b"))
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			t.Fatalf("OpenRoot() error = %v", err)
		}
		defer root.Close()
		policy := defaultScanPolicy
		policy.maximumRootEntries = 1
		if _, err := scanRoot(context.Background(), root, policy); err == nil || !strings.Contains(err.Error(), "entry limit") {
			t.Fatalf("scanRoot() error = %v, want entry limit rejection", err)
		}
	})

	t.Run("aggregate byte limit precedes reads", func(t *testing.T) {
		rootPath := t.TempDir()
		writeInventoryFixture(t, rootPath, "README.md", []byte{0, 1})
		writeInventoryFixture(t, rootPath, "package.json", []byte("{}"))
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			t.Fatalf("OpenRoot() error = %v", err)
		}
		defer root.Close()
		policy := defaultScanPolicy
		policy.maximumAggregateBytes = 3
		readCount := 0
		reader := func(*os.Root, candidate, int64, int64) ([]byte, error) {
			readCount++
			return nil, nil
		}
		if _, err := scanRootWithCandidateReader(context.Background(), root, policy, reader); err == nil || !strings.Contains(err.Error(), "aggregate byte limit") {
			t.Fatalf("scanRoot() error = %v, want aggregate preflight rejection", err)
		}
		if readCount != 0 {
			t.Fatalf("aggregate preflight performed %d content reads, want zero", readCount)
		}
	})

	t.Run("growth after preflight remains aggregate bounded", func(t *testing.T) {
		rootPath := t.TempDir()
		writeInventoryFixture(t, rootPath, "README.md", []byte("a"))
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			t.Fatalf("OpenRoot() error = %v", err)
		}
		defer root.Close()
		info, err := root.Lstat("README.md")
		if err != nil {
			t.Fatalf("Lstat() error = %v", err)
		}
		writeInventoryFixture(t, rootPath, "README.md", []byte("four"))
		value := candidate{info: info, item: catalogItem{Path: "README.md", Role: "human_overview"}}
		if _, err := readCandidate(root, value, 8, 3); err == nil || !strings.Contains(err.Error(), "aggregate byte limit") {
			t.Fatalf("readCandidate() error = %v, want aggregate limit rejection", err)
		}
	})

	t.Run("oversize and non-text files are explicit", func(t *testing.T) {
		rootPath := t.TempDir()
		writeInventoryFixture(t, rootPath, "README.md", []byte("four"))
		writeInventoryFixture(t, rootPath, "package.json", []byte{0, 1})
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			t.Fatalf("OpenRoot() error = %v", err)
		}
		defer root.Close()
		policy := defaultScanPolicy
		policy.maximumFileBytes = 3
		snapshot, err := scanRoot(context.Background(), root, policy)
		if err != nil {
			t.Fatalf("scanRoot() error = %v", err)
		}
		want := []OmittedRecognizedEntry{
			{Path: "README.md", Reason: OmissionOversize},
			{Path: "package.json", Reason: OmissionNonText},
		}
		if !slices.Equal(snapshot.Omissions.OmittedRecognized, want) {
			t.Fatalf("OmittedRecognized = %#v, want %#v", snapshot.Omissions.OmittedRecognized, want)
		}
	})
}

func TestUnsupportedPlatformFailsBeforeOpeningRepositoryRoot(t *testing.T) {
	openCount := 0
	opener := func(string) (*os.Root, error) {
		openCount++
		return nil, nil
	}
	if _, err := scanForPlatform(context.Background(), "caller-root", "windows", opener); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("scanForPlatform() error = %v, want unsupported-platform rejection", err)
	}
	if openCount != 0 {
		t.Fatalf("unsupported platform opened repository root %d time(s)", openCount)
	}
}

func TestScanPolicyBoundariesAreExact(t *testing.T) {
	t.Run("root entries", func(t *testing.T) {
		for _, test := range []struct {
			count   int
			wantErr bool
		}{{count: 1}, {count: 2}, {count: 3, wantErr: true}} {
			t.Run(strconv.Itoa(test.count), func(t *testing.T) {
				rootPath := t.TempDir()
				for index := 0; index < test.count; index++ {
					writeInventoryFixture(t, rootPath, string(rune('a'+index)), []byte("x"))
				}
				root, err := os.OpenRoot(rootPath)
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				policy := defaultScanPolicy
				policy.maximumRootEntries = 2
				snapshot, err := scanRoot(context.Background(), root, policy)
				if test.wantErr {
					if err == nil || !strings.Contains(err.Error(), "entry limit") {
						t.Fatalf("scanRoot() error = %v, want entry-limit rejection", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("scanRoot() error = %v", err)
				}
				assertInventoryRoundTrip(t, snapshot)
			})
		}
	})

	t.Run("file bytes", func(t *testing.T) {
		for _, size := range []int{2, 3, 4} {
			t.Run(strconv.Itoa(size), func(t *testing.T) {
				rootPath := t.TempDir()
				writeInventoryFixture(t, rootPath, "README.md", bytes.Repeat([]byte("x"), size))
				root, err := os.OpenRoot(rootPath)
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				policy := defaultScanPolicy
				policy.maximumFileBytes = 3
				snapshot, err := scanRoot(context.Background(), root, policy)
				if err != nil {
					t.Fatalf("scanRoot() error = %v", err)
				}
				if size <= 3 {
					if len(snapshot.Entries) != 1 || len(snapshot.Omissions.OmittedRecognized) != 0 {
						t.Fatalf("size %d snapshot = %#v, want observed entry", size, snapshot)
					}
				} else if len(snapshot.Entries) != 0 || !slices.Equal(snapshot.Omissions.OmittedRecognized, []OmittedRecognizedEntry{{Path: "README.md", Reason: OmissionOversize}}) {
					t.Fatalf("size %d snapshot = %#v, want explicit oversize omission", size, snapshot)
				}
				assertInventoryRoundTrip(t, snapshot)
			})
		}
	})

	t.Run("aggregate bytes", func(t *testing.T) {
		for _, total := range []int{3, 4, 5} {
			t.Run(strconv.Itoa(total), func(t *testing.T) {
				rootPath := t.TempDir()
				writeInventoryFixture(t, rootPath, "README.md", []byte("xx"))
				writeInventoryFixture(t, rootPath, "package.json", bytes.Repeat([]byte("y"), total-2))
				root, err := os.OpenRoot(rootPath)
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				policy := defaultScanPolicy
				policy.maximumAggregateBytes = 4
				policy.maximumFileBytes = 8
				snapshot, err := scanRoot(context.Background(), root, policy)
				if total == 5 {
					if err == nil || !strings.Contains(err.Error(), "aggregate byte limit") {
						t.Fatalf("scanRoot() error = %v, want aggregate-limit rejection", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("scanRoot() error = %v", err)
				}
				assertInventoryRoundTrip(t, snapshot)
			})
		}
	})
}

func assertInventoryRoundTrip(t *testing.T, snapshot Snapshot) {
	t.Helper()
	content, err := stablejson.Marshal(snapshot.JSONValue())
	if err != nil {
		t.Fatalf("stablejson.Marshal() error = %v", err)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("DecodeJSON() error = %v", err)
	}
	admitted, err := AdmitOutput(value)
	if err != nil {
		t.Fatalf("AdmitOutput() error = %v", err)
	}
	if admitted.InventoryID != snapshot.InventoryID {
		t.Fatalf("round-trip inventory id = %q, want %q", admitted.InventoryID, snapshot.InventoryID)
	}
}

func TestInventoryIdentityBindsEverySemanticOperand(t *testing.T) {
	base := Snapshot{
		Entries: []Entry{{
			ByteLength:    7,
			ContentSHA256: digest.SHA256BytesRef([]byte("content")),
			Path:          "README.md",
			Role:          "human_overview",
			SyntaxState:   "not_evaluated",
		}},
		Omissions: Omissions{
			OmittedRecognized: []OmittedRecognizedEntry{{Path: "package.json", Reason: OmissionNonText}},
			RootEntryCount:    3,
			UnrecognizedCount: 1,
		},
	}
	base, err := finalize(base)
	if err != nil {
		t.Fatalf("finalize(base) error = %v", err)
	}
	mutations := map[string]func(*Snapshot){
		"entry byte length":        func(value *Snapshot) { value.Entries[0].ByteLength++ },
		"entry content digest":     func(value *Snapshot) { value.Entries[0].ContentSHA256 = digest.SHA256BytesRef([]byte("changed")) },
		"entry path":               func(value *Snapshot) { value.Entries[0].Path = "AGENTS.md" },
		"entry role":               func(value *Snapshot) { value.Entries[0].Role = "agent_instructions" },
		"entry syntax state":       func(value *Snapshot) { value.Entries[0].SyntaxState = "evaluated" },
		"omitted path":             func(value *Snapshot) { value.Omissions.OmittedRecognized[0].Path = "pyproject.toml" },
		"omitted reason":           func(value *Snapshot) { value.Omissions.OmittedRecognized[0].Reason = OmissionOversize },
		"root entry count":         func(value *Snapshot) { value.Omissions.RootEntryCount++ },
		"unrecognized entry count": func(value *Snapshot) { value.Omissions.UnrecognizedCount++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := Snapshot{
				Entries: append([]Entry(nil), base.Entries...),
				Omissions: Omissions{
					OmittedRecognized: append([]OmittedRecognizedEntry(nil), base.Omissions.OmittedRecognized...),
					RootEntryCount:    base.Omissions.RootEntryCount,
					UnrecognizedCount: base.Omissions.UnrecognizedCount,
				},
			}
			mutate(&candidate)
			candidate, err = finalize(candidate)
			if err != nil {
				t.Fatalf("finalize(mutant) error = %v", err)
			}
			if candidate.InventoryID == base.InventoryID {
				t.Fatalf("%s did not change inventory identity", name)
			}
		})
	}
	identity := identityValue(base)
	assertExactKeys(t, identity, []string{"entries", "inventoryKind", "nonClaims", "omissions", "policyId", "schemaVersion", "scope"})
	identityBytes, err := stablejson.Marshal(identity)
	if err != nil {
		t.Fatalf("marshal identity value: %v", err)
	}
	wantID := digest.SHA256BytesRef(identityBytes)
	if base.InventoryID != wantID {
		t.Fatalf("inventory identity = %q, want full-record identity %q", base.InventoryID, wantID)
	}
}

func TestInventoryOutputByteLimitIsExact(t *testing.T) {
	snapshot, err := finalize(Snapshot{})
	if err != nil {
		t.Fatalf("finalize() error = %v", err)
	}
	encoded, err := stablejson.Marshal(snapshot.JSONValue())
	if err != nil {
		t.Fatalf("stablejson.Marshal() error = %v", err)
	}
	if err := validateOutputByteLimit(snapshot, len(encoded)); err != nil {
		t.Fatalf("exact output byte limit rejected: %v", err)
	}
	if err := validateOutputByteLimit(snapshot, len(encoded)-1); err == nil {
		t.Fatal("one-over output survived the byte limit")
	}
}

func TestScanHonorsCancellationBeforeFilesystemAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Scan(ctx, filepath.Join(t.TempDir(), "missing"))
	if err != context.Canceled {
		t.Fatalf("Scan() error = %v, want context.Canceled", err)
	}
}

func TestAdmitOutputRejectsIdentityAndPartitionDrift(t *testing.T) {
	root := t.TempDir()
	writeInventoryFixture(t, root, "README.md", []byte("example"))
	snapshot, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	decode := func(t *testing.T) map[string]any {
		t.Helper()
		encoded, err := stablejson.Marshal(snapshot.JSONValue())
		if err != nil {
			t.Fatalf("stablejson.Marshal() error = %v", err)
		}
		decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
		if err != nil {
			t.Fatalf("DecodeJSON() error = %v", err)
		}
		return decoded.(map[string]any)
	}

	t.Run("identity", func(t *testing.T) {
		record := decode(t)
		record["inventoryId"] = digest.SHA256BytesRef([]byte("different"))
		if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("AdmitOutput() error = %v, want identity rejection", err)
		}
	})

	t.Run("partition", func(t *testing.T) {
		record := decode(t)
		omissions := record["omissions"].(map[string]any)
		omissions["unrecognizedCount"] = omissions["rootEntryCount"]
		if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "partition") {
			t.Fatalf("AdmitOutput() error = %v, want partition rejection", err)
		}
	})

	t.Run("catalog role", func(t *testing.T) {
		record := decode(t)
		entries := record["entries"].([]any)
		entries[0].(map[string]any)["role"] = "ecosystem_manifest"
		if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "catalog") {
			t.Fatalf("AdmitOutput() error = %v, want catalog-role rejection", err)
		}
	})

	t.Run("observed and omitted overlap", func(t *testing.T) {
		record := decode(t)
		omissions := record["omissions"].(map[string]any)
		omissions["omittedRecognized"] = []any{map[string]any{"path": "README.md", "reason": OmissionNonText}}
		omissions["rootEntryCount"] = jsonNumber("2")
		if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "disjoint") {
			t.Fatalf("AdmitOutput() error = %v, want overlap rejection", err)
		}
	})
}

func assertExactKeys(t *testing.T, record map[string]any, want []string) {
	t.Helper()
	got := make([]string, 0, len(record))
	for key := range record {
		got = append(got, key)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("record keys = %v, want %v", got, want)
	}
}

func writeInventoryFixture(t *testing.T, root, name string, content []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), content, 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", name, err)
	}
}

func jsonNumber(value string) any {
	decoded, err := admission.DecodeJSON(strings.NewReader(value), int64(len(value)))
	if err != nil {
		panic(err)
	}
	return decoded
}
