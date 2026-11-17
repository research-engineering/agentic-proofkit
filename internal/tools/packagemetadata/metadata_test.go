package packagemetadata

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdmitPreservesSelectedStringsAndAllowsOtherSourceFields(t *testing.T) {
	const source = `{
		"name":" @fixture/package ",
		"version":" 1.2.3 ",
		"description":"  caf\u00e9\ne\u0301\t ",
		"license":" MIT ",
		"repository":{"type":" git ","url":" https://example.test/repo.git ","directory":"src"},
		"scripts":{"build":"echo synthetic"},"private":true,"other":null
	}`
	want := Record{
		Name: " @fixture/package ", Version: " 1.2.3 ", Description: "  caf\u00e9\ne\u0301\t ",
		License: " MIT ", Repository: Repository{Type: " git ", URL: " https://example.test/repo.git "},
	}
	input := []byte(source)
	got, err := Admit(input)
	if err != nil || got != want {
		t.Fatalf("Admit() = %#v, %v; want original strings %#v", got, err, want)
	}
	if !bytes.Equal(input, []byte(source)) {
		t.Fatal("Admit() mutated caller bytes")
	}
	clear(input)
	if got != want {
		t.Fatal("admitted record retained mutable caller storage")
	}
}

func TestAdmitAllowsAbsentAndEmptySelectedStrings(t *testing.T) {
	for _, source := range []string{
		`{}`, `{"repository":{}}`,
		`{"name":""}`, `{"version":""}`, `{"description":""}`, `{"license":""}`,
		`{"repository":{"type":""}}`, `{"repository":{"url":""}}`,
		`{"name":"","version":"","description":"","license":"","repository":{"type":"","url":""}}`,
	} {
		got, err := Admit([]byte(source))
		if err != nil || got != (Record{}) {
			t.Fatalf("Admit(%s) = %#v, %v; want empty record", source, got, err)
		}
	}
	for _, testCase := range []struct {
		source string
		want   Record
	}{
		{`{"name":"fixture"}`, Record{Name: "fixture"}},
		{`{"version":"1.2.3"}`, Record{Version: "1.2.3"}},
		{`{"description":"fixture description"}`, Record{Description: "fixture description"}},
		{`{"license":"MIT"}`, Record{License: "MIT"}},
		{`{"repository":{"type":"git"}}`, Record{Repository: Repository{Type: "git"}}},
		{`{"repository":{"url":"https://example.test/repo"}}`, Record{Repository: Repository{URL: "https://example.test/repo"}}},
	} {
		got, err := Admit([]byte(testCase.source))
		if err != nil || got != testCase.want {
			t.Fatalf("Admit(%s) = %#v, %v; want %#v", testCase.source, got, err, testCase.want)
		}
	}
}

func TestAdmitRejectsEveryNonStringSelectedType(t *testing.T) {
	for _, field := range []struct {
		label, source string
	}{
		{"name", `{"name":%s}`},
		{"version", `{"version":%s}`},
		{"description", `{"description":%s}`},
		{"license", `{"license":%s}`},
		{"repository.type", `{"repository":{"type":%s}}`},
		{"repository.url", `{"repository":{"url":%s}}`},
	} {
		for _, value := range []string{`null`, `42`, `1.5`, `true`, `false`, `[]`, `["synthetic-private-value"]`, `{}`, `{"synthetic-private-key":"synthetic-private-value"}`} {
			t.Run(field.label+"/"+value, func(t *testing.T) {
				metadataRequireError(t, fmt.Sprintf(field.source, value), "package metadata "+field.label+" must be a string")
			})
		}
	}
}

func TestAdmitRejectsNonObjectRepository(t *testing.T) {
	for _, value := range []string{`null`, `"https://example.test/repo"`, `42`, `true`, `false`, `[]`, `[{}]`} {
		metadataRequireError(t, `{"repository":`+value+`}`, "package metadata repository must be an object")
	}
}

func TestAdmitRejectsCaseVariantsAndDuplicates(t *testing.T) {
	for _, source := range []string{
		`{"Name":"fixture"}`, `{"Version":"1.2.3"}`, `{"Description":"fixture"}`, `{"License":"MIT"}`,
		`{"Repository":{}}`, `{"repository":{"Type":"git"}}`, `{"repository":{"URL":"https://example.test/repo"}}`,
		`{"name":"fixture","NAME":"other"}`, `{"version":"1.2.3","VERSION":"1.2.4"}`,
		`{"description":"fixture","DESCRIPTION":"other"}`, `{"license":"MIT","LICENSE":"ISC"}`,
		`{"repository":{},"REPOSITORY":{}}`, `{"repository":{"type":"git","TYPE":"other"}}`,
		`{"repository":{"url":"https://example.test/one","Url":"https://example.test/two"}}`,
		`{"name":"one","name":"two"}`, `{"version":"1.2.3","version":"1.2.4"}`,
		`{"description":"one","description":"two"}`, `{"license":"MIT","license":"ISC"}`,
		`{"repository":{},"repository":{}}`, `{"repository":{"type":"git","type":"other"}}`,
		`{"repository":{"url":"https://example.test/one","url":"https://example.test/two"}}`,
		`{"na\u006de":"one","name":"two"}`, `{"repository":{"u\u0072l":"one","url":"two"}}`,
		`{"other":1,"other":2}`, `{"scripts":{"build":"one","build":"two"}}`,
	} {
		t.Run(source, func(t *testing.T) {
			got, err := Admit([]byte(source))
			if err == nil || got != (Record{}) {
				t.Fatalf("Admit() = %#v, %v; want refusal and no partial record", got, err)
			}
		})
	}
}

func TestAdmitRejectsSecretLikeOriginalsWithFixedFieldErrors(t *testing.T) {
	for _, testCase := range []struct {
		label, source string
	}{
		{"name", `{"name":"api_key=synthetic-fixture-value"}`},
		{"version", `{"version":"api_key=synthetic-fixture-value"}`},
		{"description", `{"description":"api_key=synthetic-fixture-value"}`},
		{"license", `{"license":"api_key=synthetic-fixture-value"}`},
		{"repository.type", `{"repository":{"type":"api_key=synthetic-fixture-value"}}`},
		{"repository.url", `{"repository":{"url":"https://fixture:synthetic-fixture-value@example.test/repo"}}`},
		{"description", `{"description":"api_\u200bkey=synthetic-fixture-value"}`},
		{"description", `{"description":" api_key=synthetic-fixture-value "}`},
	} {
		t.Run(testCase.label+"/"+testCase.source, func(t *testing.T) {
			metadataRequireError(t, testCase.source, "package metadata "+testCase.label+" contains a secret-like value")
		})
	}
	// Only selected public fields belong to this owner; consumer policy may be stricter.
	if _, err := Admit([]byte(`{"scripts":{"build":"api_key=synthetic-fixture-value"},"repository":{"extra":"api_key=synthetic-fixture-value"}}`)); err != nil {
		t.Fatalf("unselected source fields were screened: %v", err)
	}
}

func TestAdmitRejectsMalformedOrNonObjectJSONWithoutDisclosure(t *testing.T) {
	for _, source := range []string{
		``, `[]`, `"synthetic-private-value"`, `42`, `true`, `false`,
		`{"description":"synthetic-private-value"`, `{"description":synthetic-private-value}`,
		`{"synthetic-private-key":1,"synthetic-private-key":2}`, `{} {}`,
		`{"name":"\ud800"}`, "{\"name\":\"\xff\"}",
	} {
		metadataRequireError(t, source, "package metadata JSON admission failed")
	}
	metadataRequireError(t, `null`, "package metadata must be an object")
	metadataRequireError(t, `{"repository":{"URL":"synthetic-private-value"}}`, "package metadata repository JSON admission failed")
}

func TestMetadataByteLimit(t *testing.T) {
	if MaximumBytes != 16<<20 {
		t.Fatalf("MaximumBytes = %d, want 16 MiB", MaximumBytes)
	}
	content := append([]byte(`{}`), bytes.Repeat([]byte(" "), (16<<20)-2)...)
	if _, err := Admit(content); err != nil {
		t.Fatalf("exact 16 MiB should be admitted: %v", err)
	}
	metadataRequireError(t, string(append(content, ' ')), "package metadata JSON admission failed")
	root := t.TempDir()
	path := filepath.Join(root, "package.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root); err != nil {
		t.Fatalf("Read() refused exact 16 MiB: %v", err)
	}
	if err := os.WriteFile(path, append(content, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(root); err == nil || got != (Record{}) {
		t.Fatalf("Read() admitted oversized source: %#v, %v", got, err)
	}
}

func TestReadCapturesAndAdmitsPackageJSON(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "package.json")
	if err := os.WriteFile(path, []byte(`{"name":"fixture","version":"1.2.3","repository":{"type":"git","url":"https://example.test/repo"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	want := Record{Name: "fixture", Version: "1.2.3", Repository: Repository{Type: "git", URL: "https://example.test/repo"}}
	got, err := Read(root)
	if err != nil || got != want {
		t.Fatalf("Read() = %#v, %v; want %#v", got, err, want)
	}
	if err := os.WriteFile(path, []byte(`{"description":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(root); err == nil || err.Error() != "package metadata description must be a string" || got != (Record{}) {
		t.Fatalf("Read() bypassed admission: %#v, %v", got, err)
	}
}

func TestReadRejectsMissingNonRegularAndSymlinkSources(t *testing.T) {
	for _, kind := range []string{"missing", "directory", "external symlink", "internal symlink", "dangling symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			target := filepath.Join(outside, "sentinel.json")
			if err := os.WriteFile(target, []byte(`{"name":"outside"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "package.json")
			switch kind {
			case "directory":
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
			case "external symlink", "internal symlink", "dangling symlink":
				if kind == "internal symlink" {
					target = filepath.Join(root, "source.json")
					if err := os.WriteFile(target, []byte(`{"name":"inside"}`), 0o600); err != nil {
						t.Fatal(err)
					}
				} else if kind == "dangling symlink" {
					target = filepath.Join(root, "missing.json")
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := Read(root); err == nil || got != (Record{}) {
				t.Fatalf("Read() admitted unsafe source: %#v, %v", got, err)
			}
			content, err := os.ReadFile(filepath.Join(outside, "sentinel.json"))
			if err != nil || string(content) != `{"name":"outside"}` {
				t.Fatalf("outside source changed: %q, %v", content, err)
			}
		})
	}
}

func metadataRequireError(t *testing.T, source, want string) {
	t.Helper()
	got, err := Admit([]byte(source))
	if err == nil || err.Error() != want || got != (Record{}) {
		t.Fatalf("Admit() = %#v, %v; want empty record and fixed error %q", got, err, want)
	}
	if strings.Contains(err.Error(), "synthetic-private") || strings.Contains(err.Error(), "synthetic-fixture") {
		t.Fatal("error disclosed an input key or value")
	}
}
