package pathpattern

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

type Pattern struct {
	exactPrefix string
	regexp      *regexp.Regexp
	source      string
}

func Compile(pattern string, context string) (Pattern, error) {
	safePattern, err := admit.SafeRepoRelativePath(pattern, context)
	if err != nil {
		return Pattern{}, err
	}
	compiled := Pattern{source: safePattern}
	if strings.Contains(safePattern, "*") {
		compiled.regexp = globToRegexp(safePattern)
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

func globToRegexp(pattern string) *regexp.Regexp {
	var builder strings.Builder
	builder.WriteByte('^')
	for index := 0; index < len(pattern); index++ {
		char := pattern[index]
		if char == '*' && index+1 < len(pattern) && pattern[index+1] == '*' {
			if index+2 < len(pattern) && pattern[index+2] == '/' {
				builder.WriteString("(?:.*/)?")
				index += 2
			} else {
				builder.WriteString(".*")
				index++
			}
			continue
		}
		if char == '*' {
			builder.WriteString("[^/]*")
			continue
		}
		builder.WriteString(regexp.QuoteMeta(string(char)))
	}
	builder.WriteByte('$')
	return regexp.MustCompile(builder.String())
}
