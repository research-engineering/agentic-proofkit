package requirementsourcemodel

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

var placeholderPattern = regexp.MustCompile(`(?i)\b(?:fixme|todo|tbd)\b`)
var parameterPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
var parameterReferencePattern = regexp.MustCompile(`\$\{([a-z][a-z0-9_]*)\}`)

var claimLevelVariants = []ClaimLevel{ClaimAdvisory, ClaimBlocking, ClaimDeferred}
var riskClassVariants = []RiskClass{RiskCritical, RiskHigh, RiskLow, RiskMedium}
var lifecycleStateVariants = []LifecycleState{LifecycleActive, LifecycleDeprecated, LifecycleRemoved, LifecycleSuperseded}
var termKindVariants = []TermKind{TermAction, TermObservable, TermState, TermSubject, TermValue}
var sourceKindVariants = []SourceKind{SourceClarification, SourceCodeSnapshot, SourceDesign, SourceOwnerDecision, SourcePlan}
var objectFormatVariants = []ObjectFormat{ObjectSHA1, ObjectSHA256}

type ValidationError struct {
	Code string
	Path string
}

func (err *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", err.Code, err.Path)
}

func ErrorCode(err error) string {
	if typed, ok := err.(*ValidationError); ok {
		return typed.Code
	}
	return ""
}

func invalid(code string, path string) error {
	return &ValidationError{Code: code, Path: path}
}

func canonicalID(value string, prefix string, path string) (string, error) {
	admitted, err := admit.RuleID(value, path)
	if err != nil || !strings.HasPrefix(admitted, prefix) || len(admitted) == len(prefix) {
		return "", invalid("invalid_id", path)
	}
	return admitted, nil
}

func canonicalExternalID(value string, path string) (string, error) {
	admitted, err := admit.RuleID(value, path)
	if err != nil {
		return "", invalid("invalid_id", path)
	}
	return admitted, nil
}

func canonicalText(value string, path string, allowEmpty bool, rejectPlaceholders bool) (string, error) {
	if allowEmpty && value == "" {
		return "", nil
	}
	admitted, err := admit.NonEmptyText(value, path)
	if err != nil || admitted != value {
		return "", invalid("invalid_text", path)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return "", invalid("invalid_text", path)
		}
	}
	if rejectPlaceholders && placeholderPattern.MatchString(value) {
		return "", invalid("placeholder_text", path)
	}
	return value, nil
}

func canonicalPath(value string, path string) (string, error) {
	admitted, err := admit.SafeRepoRelativePath(value, path)
	if err != nil || admitted != value {
		return "", invalid("invalid_path", path)
	}
	return admitted, nil
}

func normalizeIDs(values []string, prefix string, path string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, invalid("empty_collection", path)
	}
	result := make([]string, len(values))
	for index, value := range values {
		admitted, err := canonicalID(value, prefix, fmt.Sprintf("%s[%d]", path, index))
		if err != nil {
			return nil, err
		}
		result[index] = admitted
	}
	return sortUnique(result, path)
}

func normalizeTexts(values []string, path string, allowEmpty bool, rejectPlaceholders bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, invalid("empty_collection", path)
	}
	result := make([]string, len(values))
	for index, value := range values {
		admitted, err := canonicalText(value, fmt.Sprintf("%s[%d]", path, index), false, rejectPlaceholders)
		if err != nil {
			return nil, err
		}
		result[index] = admitted
	}
	return sortUnique(result, path)
}

func normalizeOrderedTexts(values []string, path string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, invalid("empty_collection", path)
	}
	result := make([]string, len(values))
	for index, value := range values {
		admitted, err := canonicalText(value, fmt.Sprintf("%s[%d]", path, index), false, true)
		if err != nil {
			return nil, err
		}
		result[index] = admitted
	}
	return result, nil
}

func normalizePaths(values []string, path string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, invalid("empty_collection", path)
	}
	result := make([]string, len(values))
	for index, value := range values {
		admitted, err := canonicalPath(value, fmt.Sprintf("%s[%d]", path, index))
		if err != nil {
			return nil, err
		}
		result[index] = admitted
	}
	return sortUnique(result, path)
}

func sortUnique(values []string, path string) ([]string, error) {
	sort.Strings(values)
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return nil, invalid("duplicate_value", path)
		}
	}
	return values, nil
}

func validClaimLevel(value ClaimLevel, path string) error {
	return validClosedVariant(value, claimLevelVariants, "invalid_claim_level", path)
}

func validRiskClass(value RiskClass, path string) error {
	return validClosedVariant(value, riskClassVariants, "invalid_risk_class", path)
}

func validLifecycleState(value LifecycleState, path string) error {
	return validClosedVariant(value, lifecycleStateVariants, "invalid_lifecycle_state", path)
}

func validTermKind(value TermKind, path string) error {
	return validClosedVariant(value, termKindVariants, "invalid_term_kind", path)
}

func validSourceKind(value SourceKind, path string) error {
	return validClosedVariant(value, sourceKindVariants, "invalid_source_kind", path)
}

func validObjectFormat(value ObjectFormat, path string) error {
	return validClosedVariant(value, objectFormatVariants, "invalid_object_format", path)
}

func validClosedVariant[T ~string](value T, variants []T, code string, path string) error {
	for _, variant := range variants {
		if value == variant {
			return nil
		}
	}
	return invalid(code, path)
}
