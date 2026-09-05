package commandroute

import (
	"regexp"
	"slices"
	"strings"
)

var tokenPattern = regexp.MustCompile(TokenPattern)

const (
	MinimumTokens      = 1
	MaximumTokens      = 4
	Separator          = " "
	TokenPattern       = `^[a-z0-9]+(?:-[a-z0-9]+)*$`
	AmbiguityPolicy    = "no_route_is_prefix_of_another"
	OmittedRoutePolicy = "command_id"
)

func Valid(tokens []string) bool {
	if len(tokens) < MinimumTokens || len(tokens) > MaximumTokens {
		return false
	}
	for _, token := range tokens {
		if !ValidToken(token) {
			return false
		}
	}
	return true
}

func ValidToken(token string) bool {
	return tokenPattern.MatchString(token)
}

// Resolve returns the effective route. A nil route is omitted and therefore
// resolves to the stable command identity; an explicitly empty route is invalid.
func Resolve(commandID string, route []string) ([]string, bool) {
	if !ValidToken(commandID) {
		return nil, false
	}
	if route == nil {
		return []string{commandID}, true
	}
	if !Valid(route) {
		return nil, false
	}
	return slices.Clone(route), true
}

func Parse(text string) ([]string, bool) {
	tokens := strings.Split(text, Separator)
	if !Valid(tokens) {
		return nil, false
	}
	return tokens, true
}

func Prefix(prefix, value []string) bool {
	return len(prefix) < len(value) && slices.Equal(prefix, value[:len(prefix)])
}

func Key(tokens []string) string {
	return strings.Join(tokens, "\x00")
}

func Text(tokens []string) string {
	return strings.Join(tokens, Separator)
}
