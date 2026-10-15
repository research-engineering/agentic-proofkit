// Package pathidentity owns conservative, platform-portable path equivalence.
package pathidentity

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	MaximumBytes      = 1024
	MaximumComponents = 64
)

type Prefix struct {
	Key  string
	Path string
}

// Dialect is a closed wire-compatibility selector, not a caller policy. New
// operations use CanonicalCaseless; Legacy is reserved for retained v1/v2.
type Dialect uint8

const (
	Legacy Dialect = iota + 1
	CanonicalCaseless
)

func Key(value string) (string, error) {
	return CanonicalCaseless.Key(value)
}

func (dialect Dialect) Key(value string) (string, error) {
	if err := validate(value); err != nil {
		return "", err
	}
	switch dialect {
	case Legacy:
		// Frozen Fold(NFC) includes the old stream-safe normalization behavior.
		return cases.Fold().String(norm.NFC.String(value)), nil
	case CanonicalCaseless:
		for index := 0; index < len(value); index++ {
			if value[index] >= utf8.RuneSelf {
				return canonicalNFD(defaultCaseFold(canonicalNFD(value))), nil
			}
		}
		// ASCII is already NFD; default case folding changes only A-Z.
		return strings.ToLower(value), nil
	default:
		return "", fmt.Errorf("path identity dialect is invalid")
	}
}

// Unicode default folding keeps Cherokee uppercase. x/text v0.42.0 toggles
// these case pairs; this correction must not change the frozen legacy codec.
func defaultCaseFold(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cherokee, r) {
			return unicode.ToUpper(r)
		}
		return r
	}, cases.Fold().String(value))
}

func Prefixes(value string) ([]Prefix, error) {
	return CanonicalCaseless.Prefixes(value)
}

func (dialect Dialect) Prefixes(value string) ([]Prefix, error) {
	if _, err := dialect.Key(value); err != nil {
		return nil, err
	}
	components := strings.Split(value, "/")
	prefixes := make([]Prefix, 0, len(components))
	for index := range components {
		prefixPath := strings.Join(components[:index+1], "/")
		prefixKey, err := dialect.Key(prefixPath)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, Prefix{Key: prefixKey, Path: prefixPath})
	}
	return prefixes, nil
}

func Overlaps(left, right string) (bool, error) {
	return CanonicalCaseless.Overlaps(left, right)
}

func (dialect Dialect) Overlaps(left, right string) (bool, error) {
	leftKey, err := dialect.Key(left)
	if err != nil {
		return false, err
	}
	rightKey, err := dialect.Key(right)
	if err != nil {
		return false, err
	}
	return leftKey == rightKey || withinKey(leftKey, rightKey) || withinKey(rightKey, leftKey), nil
}

// Unicode 17 D145 needs true NFD, not x/text's whole-string stream-safe
// transform. A single scalar's canonical expansion is below its stream-safe
// threshold in the pinned tables (including recursive and Hangul expansion).
// Stable ordering of complete non-starter runs retains authored CCC0 barriers
// such as CGJ and slash without inserting, deleting or truncating scalars.
func canonicalNFD(value string) string {
	type scalar struct {
		value rune
		ccc   uint8
	}
	scalars := make([]scalar, 0, len(value))
	for _, source := range value {
		for _, expanded := range norm.NFD.String(string(source)) {
			scalars = append(scalars, scalar{expanded, norm.NFD.PropertiesString(string(expanded)).CCC()})
		}
	}
	order := func(start, end int) {
		run := scalars[start:end]
		sort.SliceStable(run, func(left, right int) bool { return run[left].ccc < run[right].ccc })
	}
	start := 0
	for index, item := range scalars {
		if item.ccc == 0 {
			order(start, index)
			start = index + 1
		}
	}
	order(start, len(scalars))
	var result strings.Builder
	for _, item := range scalars {
		result.WriteRune(item.value)
	}
	return result.String()
}

func withinKey(candidate, ancestor string) bool {
	return len(candidate) > len(ancestor) && candidate[:len(ancestor)] == ancestor && candidate[len(ancestor)] == '/'
}

func validate(value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("path identity requires valid UTF-8")
	}
	if value == "" || len(value) > MaximumBytes || strings.HasPrefix(value, "/") || strings.Contains(value, `\`) || path.Clean(value) != value || value == "." {
		return fmt.Errorf("path identity requires a bounded canonical relative POSIX path")
	}
	components := strings.Split(value, "/")
	if len(components) > MaximumComponents {
		return fmt.Errorf("path identity exceeds its component limit")
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("path identity requires canonical components")
		}
	}
	return nil
}

// ContainsComponentEquivalent reports whether any component of a canonical
// relative path names reserved on a supported filesystem. Besides canonical
// caseless equivalence, HFS+ drops the ignorable scalars Git rejects in .git;
// reserved and every component are normalized identically, and a reserved
// name whose visible form is empty, "." or ".." is invalid.
func ContainsComponentEquivalent(value, reserved string) (bool, error) {
	reservedKey, err := CanonicalCaseless.Key(hfsVisible(reserved))
	if err != nil || strings.Contains(reserved, "/") {
		return false, fmt.Errorf("reserved path component is invalid")
	}
	if _, err := CanonicalCaseless.Key(value); err != nil {
		return false, err
	}
	for _, component := range strings.Split(value, "/") {
		visible := hfsVisible(component)
		if visible == "" {
			continue
		}
		key, err := CanonicalCaseless.Key(visible)
		if err != nil {
			return false, err
		}
		if key == reservedKey {
			return true, nil
		}
	}
	return false, nil
}

func hfsVisible(component string) string {
	return strings.Map(func(r rune) rune {
		if hfsIgnorable(r) {
			return -1
		}
		return r
	}, component)
}

func hfsIgnorable(r rune) bool {
	return r >= 0x200c && r <= 0x200f || r >= 0x202a && r <= 0x202e || r >= 0x206a && r <= 0x206f || r == 0xfeff
}
