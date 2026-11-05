package pathpattern

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

type Pattern struct {
	exactPrefix string
	regexp      *regexp.Regexp
	source      string
}

func Compile(pattern string, context string) (Pattern, error) {
	if !utf8.ValidString(pattern) {
		return Pattern{}, fmt.Errorf("%s must be valid UTF-8", context)
	}
	safePattern, err := admit.SafeRepoRelativePath(pattern, context)
	if err != nil {
		return Pattern{}, err
	}
	compiled := Pattern{source: safePattern}
	if strings.Contains(safePattern, "*") {
		compiled.regexp, err = globToRegexp(safePattern)
		if err != nil {
			return Pattern{}, fmt.Errorf("%s exceeds the path-pattern compiler limits", context)
		}
	} else {
		compiled.exactPrefix = strings.TrimSuffix(safePattern, "/")
	}
	return compiled, nil
}

func CompileAll(patterns []string, context string) ([]Pattern, error) {
	compiled := make([]Pattern, 0, len(patterns))
	for index, pattern := range patterns {
		value, err := Compile(pattern, fmt.Sprintf("%s[%d]", context, index))
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, value)
	}
	return compiled, nil
}

func (pattern Pattern) String() string {
	return pattern.source
}

// MatchesAllRootNames tests the wildcard-only language, not a sample of paths:
// literals exclude some names; matching one root name then excludes required slashes.
func (pattern Pattern) MatchesAllRootNames() bool {
	return strings.Trim(pattern.source, "*/") == "" && pattern.MatchAdmitted("x")
}

func (pattern Pattern) MatchAdmitted(target string) bool {
	if pattern.regexp != nil {
		return pattern.regexp.MatchString(target)
	}
	return target == pattern.exactPrefix || strings.HasPrefix(target, pattern.exactPrefix+"/")
}

func (pattern Pattern) Match(target string) bool {
	safeTarget, err := admit.SafeRepoRelativePath(target, "path")
	return err == nil && pattern.MatchAdmitted(safeTarget)
}

func Match(pattern string, target string) bool {
	compiled, err := Compile(pattern, "path pattern")
	if err != nil {
		return false
	}
	return compiled.Match(target)
}

func MatchAny(patterns []string, target string) bool {
	for _, pattern := range patterns {
		if Match(pattern, target) {
			return true
		}
	}
	return false
}

func Validate(pattern string, context string) error {
	_, err := Compile(pattern, context)
	return err
}

// A repo-relative glob is anchored to the repository root. A matching
// directory covers its descendants, as does a literal selector. Within a
// segment, * never crosses a slash; only a complete ** segment can do so.
func globToRegexp(pattern string) (*regexp.Regexp, error) {
	var builder strings.Builder
	builder.WriteByte('^')
	segments := strings.Split(pattern, "/")
	for index, segment := range segments {
		last := index == len(segments)-1
		if segment == "**" {
			if last {
				builder.WriteString(".*")
			} else {
				builder.WriteString("(?:[^/]+/)*")
			}
			continue
		}
		for partIndex, part := range strings.Split(segment, "*") {
			if partIndex > 0 {
				builder.WriteString("[^/]*")
			}
			builder.WriteString(regexp.QuoteMeta(part))
		}
		if !last {
			builder.WriteByte('/')
		}
	}
	builder.WriteString("(?:/.*)?$")
	return regexp.Compile(builder.String())
}
