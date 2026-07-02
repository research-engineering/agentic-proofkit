package pathpattern

import (
	"regexp"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func Match(pattern string, target string) bool {
	safePattern, err := admit.SafeRepoRelativePath(pattern, "path pattern")
	if err != nil {
		return false
	}
	safeTarget, err := admit.SafeRepoRelativePath(target, "path")
	if err != nil {
		return false
	}
	if strings.Contains(safePattern, "*") {
		return globToRegexp(safePattern).MatchString(safeTarget)
	}
	return safeTarget == safePattern || strings.HasPrefix(safeTarget, strings.TrimSuffix(safePattern, "/")+"/")
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
	_, err := admit.SafeRepoRelativePath(pattern, context)
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
