package unicodepolicy

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode"
)

type unsafeScalarCorpus struct {
	SchemaVersion  int                       `json:"schemaVersion"`
	UnicodeVersion string                    `json:"unicodeVersion"`
	TableSHA256    string                    `json:"tableSha256"`
	Ranges         []unsafeScalarCorpusRange `json:"ranges"`
}

type unsafeScalarCorpusRange struct {
	Category string `json:"category"`
	Start    rune   `json:"start"`
	End      rune   `json:"end"`
	Step     rune   `json:"step"`
}

func TestUnsafeScalarTableIdentityAndCardinality(t *testing.T) {
	var source strings.Builder
	source.WriteString(UnicodeVersion)
	source.WriteByte('\n')
	unsafeCount := 0
	entries := unsafeScalarRanges[:]
	entries = slices.Clone(entries)
	categoryOrder := map[string]int{"Cc": 0, "Cf": 1, "Zl": 2, "Zp": 3}
	slices.SortFunc(entries, func(left scalarRange, right scalarRange) int {
		if categoryOrder[left.category] != categoryOrder[right.category] {
			return categoryOrder[left.category] - categoryOrder[right.category]
		}
		return int(left.start - right.start)
	})
	for _, entry := range entries {
		_, _ = fmt.Fprintf(&source, "%s:%06x-%06x/%d\n", entry.category, entry.start, entry.end, entry.step)
		unsafeCount += int((entry.end-entry.start)/entry.step) + 1
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(source.String()))); got != TableSHA256 {
		t.Fatalf("table digest = %s, want %s", got, TableSHA256)
	}
	if unsafeCount != 237 {
		t.Fatalf("unsafe scalar count = %d, want 237", unsafeCount)
	}
}

func TestUnsafeScalarTableMatchesVersionedOwnerCorpus(t *testing.T) {
	content, err := os.ReadFile("testdata/unsafe-scalar-ranges.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus unsafeScalarCorpus
	if err := json.Unmarshal(content, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaVersion != 1 || corpus.UnicodeVersion != UnicodeVersion || corpus.TableSHA256 != TableSHA256 {
		t.Fatalf("Unicode owner corpus identity is stale: %#v", corpus)
	}
	if len(corpus.Ranges) != len(unsafeScalarRanges) {
		t.Fatalf("Unicode owner corpus range count=%d want %d", len(corpus.Ranges), len(unsafeScalarRanges))
	}
	for index, actual := range corpus.Ranges {
		expected := unsafeScalarRanges[index]
		if actual.Category != expected.category || actual.Start != expected.start || actual.End != expected.end || actual.Step != expected.step {
			t.Fatalf("Unicode owner corpus range %d=%#v want %#v", index, actual, expected)
		}
	}
}

func TestUnsafeScalarClassification(t *testing.T) {
	for _, value := range []rune{0x0000, 0x007f, 0x0085, 0x00ad, 0x061c, 0x200b, 0x2028, 0x2029, 0xe0001} {
		if !IsUnsafeScalar(value) {
			t.Fatalf("U+%04X was not classified unsafe", value)
		}
	}
	for _, value := range []rune{' ', 'a', 0x00ae, 0x0606, 0x2027, 0x1f600, 0x10ffff} {
		if IsUnsafeScalar(value) {
			t.Fatalf("U+%04X was classified unsafe", value)
		}
	}
}

func TestUnsafeScalarTableMatchesEveryUnicode17Scalar(t *testing.T) {
	if unicode.Version != UnicodeVersion {
		t.Fatalf("Go Unicode version = %s, want %s", unicode.Version, UnicodeVersion)
	}
	for value := rune(0); value <= unicode.MaxRune; value++ {
		if value >= 0xd800 && value <= 0xdfff {
			continue
		}
		want := unicode.Is(unicode.Cc, value) ||
			unicode.Is(unicode.Cf, value) ||
			unicode.Is(unicode.Zl, value) ||
			unicode.Is(unicode.Zp, value)
		if got := IsUnsafeScalar(value); got != want {
			t.Fatalf("IsUnsafeScalar(U+%04X) = %t, want %t", value, got, want)
		}
	}
}

func TestValidScalarStringRejectsMalformedUTF8(t *testing.T) {
	for _, value := range []string{string([]byte{0xff}), string([]byte{0xc3, 0x28}), string([]byte{0xed, 0xa0, 0x80})} {
		if ValidScalarString(value) {
			t.Fatalf("malformed UTF-8 was accepted: %x", []byte(value))
		}
	}
	if !ValidScalarString("e\u0301 \U0001f600") {
		t.Fatal("valid scalar string was rejected")
	}
}

func TestDecodeUTF8RejectsMalformedBytesWithoutDisclosure(t *testing.T) {
	secret := []byte{'g', 'h', 'p', '_', 0xff}
	if _, err := DecodeUTF8(secret); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("DecodeUTF8 error = %v, want ErrInvalidUTF8", err)
	} else if strings.Contains(err.Error(), "ghp_") {
		t.Fatal("DecodeUTF8 disclosed rejected bytes")
	}
	decoded, err := DecodeUTF8([]byte("e\u0301 \U0001f600"))
	if err != nil || decoded != "e\u0301 \U0001f600" {
		t.Fatalf("DecodeUTF8 valid value = %q, %v", decoded, err)
	}
}
