package semversion

import (
	"strings"

	"golang.org/x/mod/semver"
)

// IsExact accepts full SemVer 2.0.0 without the Go module v-prefix or shorthand forms.
func IsExact(value string) bool {
	core, _, _ := strings.Cut(value, "-")
	core, _, _ = strings.Cut(core, "+")
	return strings.Count(core, ".") == 2 && semver.IsValid("v"+value)
}
