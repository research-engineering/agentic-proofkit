// Package pathidentity owns conservative, platform-portable path equivalence.
package pathidentity

import (
	"fmt"
	"path"
	"strings"
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

func Key(value string) (string, error) {
	if err := validate(value); err != nil {
		return "", err
	}
	return cases.Fold().String(norm.NFC.String(value)), nil
}

func Prefixes(value string) ([]Prefix, error) {
	if _, err := Key(value); err != nil {
		return nil, err
	}
	components := strings.Split(value, "/")
	prefixes := make([]Prefix, 0, len(components))
	for index := range components {
		prefixPath := strings.Join(components[:index+1], "/")
		prefixKey, err := Key(prefixPath)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, Prefix{Key: prefixKey, Path: prefixPath})
	}
	return prefixes, nil
}

func Overlaps(left, right string) (bool, error) {
	leftKey, err := Key(left)
	if err != nil {
		return false, err
	}
	rightKey, err := Key(right)
	if err != nil {
		return false, err
	}
	return leftKey == rightKey || withinKey(leftKey, rightKey) || withinKey(rightKey, leftKey), nil
}

func Within(candidate, ancestor string) (bool, error) {
	candidateKey, err := Key(candidate)
	if err != nil {
		return false, err
	}
	ancestorKey, err := Key(ancestor)
	if err != nil {
		return false, err
	}
	return withinKey(candidateKey, ancestorKey), nil
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
