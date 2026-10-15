package pathidentity

import (
	"strings"
	"testing"
)

func TestASCIIKeysPreserveAdmissionAndExactFolding(t *testing.T) {
	for value := byte(0); value < 128; value++ {
		input := "Root/x" + string(value) + "y/FILE"
		if value == '\\' {
			if _, err := Key(input); err == nil {
				t.Fatal("ASCII shortcut bypassed path admission")
			}
			continue
		}
		expected := []byte(input)
		for index, character := range expected {
			if character >= 'A' && character <= 'Z' {
				expected[index] += 'a' - 'A'
			}
		}
		for _, dialect := range []Dialect{CanonicalCaseless, Legacy} {
			actual, err := dialect.Key(input)
			if err != nil || actual != string(expected) {
				t.Fatalf("ASCII %02x dialect %d: %q, %v", value, dialect, actual, err)
			}
		}
	}
	for _, input := range []string{strings.Repeat("A", 1024), strings.Repeat("A/", 63) + "B"} {
		if _, err := Key(input); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPortableEquivalenceAndContainment(t *testing.T) {
	tests := []struct {
		left    string
		right   string
		overlap bool
	}{
		{left: "proofkit/A.json", right: "proofkit/a.json", overlap: true},
		{left: "proofkit/caf\u00e9.json", right: "proofkit/cafe\u0301.json", overlap: true},
		{left: "proofkit", right: "proofkit/a.json", overlap: true},
		{left: "proofkit/a.json", right: "docs/a.json", overlap: false},
	}
	for _, test := range tests {
		actual, err := Overlaps(test.left, test.right)
		if err != nil || actual != test.overlap {
			t.Fatalf("Overlaps(%q, %q)=%t,%v, want %t,nil", test.left, test.right, actual, err, test.overlap)
		}
	}
	if _, err := Key(string([]byte{0xff})); err == nil {
		t.Fatal("Key() admitted invalid UTF-8")
	}
	if left, _ := Key("proofkit/\u03c3.json"); left != mustKey(t, "proofkit/\u03c2.json") {
		t.Fatal("Key() did not apply Unicode case folding")
	}
	for _, value := range []string{"", "/absolute", "a/../b", "a//b", "a\\b", "./a"} {
		if _, err := Key(value); err == nil {
			t.Fatalf("Key(%q) admitted a non-canonical path", value)
		}
	}
	prefixes, err := Prefixes("Proofkit/specs/a.json")
	if err != nil || len(prefixes) != 3 || prefixes[0].Key != "proofkit" || prefixes[1].Path != "Proofkit/specs" {
		t.Fatalf("Prefixes() = %#v, %v", prefixes, err)
	}
}

func mustKey(t *testing.T, value string) string {
	t.Helper()
	key, err := Key(value)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestReservedComponentEquivalenceCoversPortableSpellings(t *testing.T) {
	for value, want := range map[string]bool{
		".git": true, ".git/hooks/pre-commit": true, ".GIT/config": true, ".Git": true,
		"vendor/module/.git/hooks/post-checkout": true, ".g\u200cit/config": true, "\ufeff.git": true,
		".gi\u200dt/hooks": true, ".git\u206a": true,
		".github/workflows/ci.yml": false, ".gitignore": false, "git/hooks": false, "docs/.git-notes": false,
		"a.git/config": false, ".g\u012bt/config": false, "a/\u200c/b": false,
	} {
		got, err := ContainsComponentEquivalent(value, ".git")
		if err != nil || got != want {
			t.Fatalf("%q: got %v %v, want %v", value, got, err, want)
		}
	}
	for _, invalid := range []string{"", "/.git", "a/../.git", `.git\hooks`} {
		if _, err := ContainsComponentEquivalent(invalid, ".git"); err == nil {
			t.Fatalf("%q admitted", invalid)
		}
	}
	for _, pair := range []struct {
		value, reserved string
		want            bool
	}{
		{".g\u200cit", ".g\u200cit", true}, {"\ufeff.git", "\ufeff.git", true},
		{".git/config", ".g\u200cit", true}, {".github", ".g\u200cit", false},
	} {
		got, err := ContainsComponentEquivalent(pair.value, pair.reserved)
		if err != nil || got != pair.want {
			t.Fatalf("%q against reserved %q: got %v %v, want %v", pair.value, pair.reserved, got, err, pair.want)
		}
	}
	for _, reserved := range []string{"", "a/b", "..", "\u200c", "\u200c\u200d", ".\u200c."} {
		if _, err := ContainsComponentEquivalent("a", reserved); err == nil {
			t.Fatalf("reserved %q admitted", reserved)
		}
	}
}
