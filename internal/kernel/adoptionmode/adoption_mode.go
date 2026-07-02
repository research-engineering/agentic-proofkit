package adoptionmode

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	Observe        = "observe"
	Warn           = "warn"
	EnforceTouched = "enforce-touched"
	EnforceAll     = "enforce-all"

	ScopeAll     = "all"
	ScopeNone    = "none"
	ScopeTouched = "touched"
)

var orderedValues = []string{EnforceAll, EnforceTouched, Observe, Warn}

var values = map[string]struct{}{
	EnforceAll:     {},
	EnforceTouched: {},
	Observe:        {},
	Warn:           {},
}

var scopeValues = map[string]struct{}{
	ScopeAll:     {},
	ScopeNone:    {},
	ScopeTouched: {},
}

func AllowedText() string {
	return admit.SortedEnum(values)
}

func AllowedScopeText() string {
	return admit.SortedEnum(scopeValues)
}

func CLIAllowedText() string {
	return "observe, warn, enforce-touched, or enforce-all"
}

func CLIScopeText() string {
	return "none, touched, or all"
}

func ValuesMap() map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range orderedValues {
		out[value] = struct{}{}
	}
	return out
}

func Admit(raw any, context string) (string, error) {
	return admit.Enum(raw, values, context)
}

func AdmitScope(raw any, context string) (string, error) {
	return admit.Enum(raw, scopeValues, context)
}

func Validate(value string, context string) (string, error) {
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, AllowedText())
	}
	return value, nil
}

func ValidateCLI(value string, flag string) (string, error) {
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s requires %s", flag, CLIAllowedText())
	}
	return value, nil
}

func ValidateScopeValue(value string, context string) (string, error) {
	if _, ok := scopeValues[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, AllowedScopeText())
	}
	return value, nil
}

func ValidateScopeCLI(value string, flag string) (string, error) {
	if _, ok := scopeValues[value]; !ok {
		return "", fmt.Errorf("%s requires %s", flag, CLIScopeText())
	}
	return value, nil
}

func IsEnforcing(mode string) bool {
	return mode == EnforceAll || mode == EnforceTouched
}

func NonEnforcingStatus(mode string) string {
	if mode == Warn {
		return "warning"
	}
	return "skipped"
}

func ScopeFailures(mode string, checkedScope string) []string {
	failures := []string{}
	if mode == EnforceAll && checkedScope != ScopeAll {
		failures = append(failures, "enforce-all requires checkedScope all")
	}
	if mode == EnforceTouched && checkedScope == ScopeNone {
		failures = append(failures, "enforce-touched requires checkedScope touched or all")
	}
	return failures
}

func ValidateScope(mode string, checkedScope string, context string) error {
	failures := ScopeFailures(mode, checkedScope)
	if len(failures) == 0 {
		return nil
	}
	if context == "" {
		return fmt.Errorf("%s", failures[0])
	}
	return fmt.Errorf("%s %s", context, failures[0])
}
