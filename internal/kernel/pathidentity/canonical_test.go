package pathidentity

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

func TestCanonicalCaselessUnicode17Corpus(t *testing.T) {
	if norm.Version != "17.0.0" || cases.UnicodeVersion != "17.0.0" || unicode.Version != "17.0.0" {
		t.Fatal("Unicode upgrade requires current and frozen legacy qualification")
	}
	content, err := os.ReadFile("testdata/d145-unicode17.json")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(content)) != "95ecb0212d115016ee5957f99bc02d01bd242d275743c73bda76d99fba684675" {
		t.Fatal("saved independent ICU 78.3 / Unicode 17 corpus changed")
	}
	var corpus struct {
		Controls []struct {
			Name, Input, NfdExpected, FoldExpected, Expected string
			PathDomain                                       bool
		}
	}
	if err := json.Unmarshal(content, &corpus); err != nil || len(corpus.Controls) != 12 {
		t.Fatal("invalid corpus")
	}
	// These are saved finite oracle expectations, not a fresh ICU execution.
	for _, row := range corpus.Controls {
		t.Run(row.Name, func(t *testing.T) {
			key, err := Key(row.Input)
			if (err == nil) != row.PathDomain {
				t.Fatal("path admission changed")
			}
			if row.PathDomain && key != row.Expected {
				t.Fatalf("key %q, want %q", key, row.Expected)
			}
			nfd := canonicalNFD(row.Input)
			if nfd != row.NfdExpected {
				t.Fatal("first NFD differs from ICU")
			}
			folded := defaultCaseFold(nfd)
			if folded != row.FoldExpected {
				t.Fatal("fold differs from ICU")
			}
			actual := canonicalNFD(folded)
			if actual != row.Expected {
				t.Fatal("second NFD differs from ICU")
			}
			if strings.Count(actual, "\u034f") != strings.Count(row.Input, "\u034f") || strings.Count(actual, "/") != strings.Count(row.Input, "/") {
				t.Fatal("barrier inserted or removed")
			}
		})
	}
}

func TestCanonicalCaseFoldCherokeeIsStableAndLegacyIsFrozen(t *testing.T) {
	// Unicode 17 CaseFolding.txt maps these lowercase ranges to uppercase.
	for _, pair := range []struct{ upper, lower, count rune }{{0x13a0, 0xab70, 80}, {0x13f0, 0x13f8, 6}} {
		for offset := rune(0); offset < pair.count; offset++ {
			upper, lower := string(pair.upper+offset), string(pair.lower+offset)
			for _, input := range []string{upper, lower} {
				got := mustKey(t, input)
				if got != upper || mustKey(t, got) != got {
					t.Fatalf("Cherokee fold input=%U got=%U want=%U", []rune(input), []rune(got), []rune(upper))
				}
			}
			oldUpper, err := Legacy.Key(upper)
			if err != nil || oldUpper != lower {
				t.Fatal("frozen legacy uppercase mapping changed")
			}
			oldLower, err := Legacy.Key(lower)
			if err != nil || oldLower != upper {
				t.Fatal("frozen legacy lowercase mapping changed")
			}
		}
	}
}

func TestCanonicalFoldPinnedUnicode17Tables(t *testing.T) {
	if norm.Version != "17.0.0" || cases.UnicodeVersion != "17.0.0" || unicode.Version != "17.0.0" {
		t.Fatal("Unicode upgrade requires current and frozen legacy qualification")
	}
	current, legacyProvider := sha256.New(), sha256.New()
	buffer := make([]byte, 0, 64)
	writeRecord := func(h hash.Hash, scalar rune, nfd, folded string, ccc byte) {
		buffer = binary.LittleEndian.AppendUint32(buffer[:0], uint32(scalar))
		buffer = binary.LittleEndian.AppendUint32(buffer, uint32(len(nfd)))
		buffer = append(buffer, nfd...)
		buffer = binary.LittleEndian.AppendUint32(buffer, uint32(len(folded)))
		buffer = append(buffer, folded...)
		buffer = append(buffer, ccc)
		_, _ = h.Write(buffer)
	}
	count := 0
	for scalar := rune(0); scalar <= utf8.MaxRune; scalar++ {
		if !utf8.ValidRune(scalar) {
			continue
		}
		value := string(scalar)
		nfd, ccc := canonicalNFD(value), norm.NFD.PropertiesString(value).CCC()
		writeRecord(current, scalar, nfd, defaultCaseFold(value), ccc)
		writeRecord(legacyProvider, scalar, nfd, cases.Fold().String(value), ccc)
		count++
	}
	if count != 1112064 {
		t.Fatal("Unicode scalar inventory changed")
	}
	// Independent ICU 78.3 / Unicode 17 enumeration, not a candidate-generated
	// golden. Each frame is scalar, NFD byte length/bytes, fold length/bytes, CCC.
	if got := fmt.Sprintf("%x", current.Sum(nil)); got != "58a6e352cfcb535b6a14c87dbe268387bcb5c7fc4c447764faede1492b6c20bf" {
		t.Fatalf("canonical Unicode 17 table mismatch: %s", got)
	}
	// This binds the old provider, not a claim that its folding matches Unicode.
	if got := fmt.Sprintf("%x", legacyProvider.Sum(nil)); got != "4a9887d2c2c34dc815c94e40979ce954720019fcde368c247024c44ac9c1e78d" {
		t.Fatalf("legacy provider changed; retained semantics require qualification: %s", got)
	}
}

func TestCanonicalCaselessExactKeysAndDialectClasses(t *testing.T) {
	for _, row := range []struct{ input, expected string }{
		{"caf\u00e9", "cafe\u0301"},
		{"\u1fb3\u030a", "\u03b1\u030a\u03b9"},
		{"\u03b1\u03b9\u030a", "\u03b1\u03b9\u030a"},
		{"\u0315\u0301\u0300\u0323", "\u0323\u0301\u0300\u0315"},
		{"a\u0315\u034f\u0323/b\u0301", "a\u0315\u034f\u0323/b\u0301"},
		{"\u212b/\uac01/\U0001d160", "a\u030a/\u1100\u1161\u11a8/\U0001d158\U0001d165\U0001d16e"},
	} {
		if got := mustKey(t, row.input); got != row.expected {
			t.Fatalf("%q: %q != %q", row.input, got, row.expected)
		}
	}
	for _, row := range []struct {
		left, right     string
		legacy, current bool
	}{
		{"docs/\u00df\u0301", "docs/s\u015b", false, true},
		{"\u1fb3\u030a", "\u03b1\u03b9\u030a", true, false},
		{"\u1fb3\u030a", "\u03b1\u030a\u03b9", false, true},
		{"a" + strings.Repeat("\u0301", 31), "a" + strings.Repeat("\u0301", 30) + "\u034f\u0301", true, false},
	} {
		for _, dialect := range []Dialect{Legacy, CanonicalCaseless} {
			left, err := dialect.Key(row.left)
			if err != nil {
				t.Fatal(err)
			}
			right, err := dialect.Key(row.right)
			if err != nil {
				t.Fatal(err)
			}
			want := row.current
			if dialect == Legacy {
				want = row.legacy
			}
			if (left == right) != want {
				t.Fatalf("dialect %d: %q / %q", dialect, left, right)
			}
		}
	}
	for _, dialect := range []Dialect{0, 255} {
		if _, err := dialect.Key("a"); err == nil {
			t.Fatal("invalid dialect accepted")
		}
	}
}

func TestCanonicalCaselessPathBoundsAndPrefixes(t *testing.T) {
	for _, input := range []string{strings.Repeat("\u0301", 512), strings.Repeat("\u0390", 341), strings.Repeat("a/", 63) + "\u1fb3\u030a"} {
		if _, err := Key(input); err != nil {
			t.Fatal(err)
		}
	}
	if key := mustKey(t, strings.Repeat("\u0390", 341)); len(key) <= MaximumBytes {
		t.Fatal("expanded key was bounded like raw input")
	}
	for _, input := range []string{strings.Repeat("a", 1025), strings.Repeat("a/", 64) + "a"} {
		if _, err := Key(input); err == nil {
			t.Fatal("raw bound removed")
		}
	}
	prefixes, err := Prefixes("\u1fb3\u030a/FILE")
	if err != nil || len(prefixes) != 2 || prefixes[0].Key != "\u03b1\u030a\u03b9" || prefixes[1].Path != "\u1fb3\u030a/FILE" {
		t.Fatalf("prefixes: %#v %v", prefixes, err)
	}
	if overlaps, err := Overlaps("\u1fb3\u030a", "\u03b1\u030a\u03b9/file"); err != nil || !overlaps {
		t.Fatal("canonical ancestor missed")
	}
}
