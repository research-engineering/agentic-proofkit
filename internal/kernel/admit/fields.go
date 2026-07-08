package admit

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

var (
	ruleIDPattern              = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(?:[._:-][A-Za-z0-9_]+)*$`)
	timestampLikePattern       = regexp.MustCompile(`\d{4}-\d{2}-\d{2}(?:T\d{2}:?\d{2}:?\d{2}(?:\.\d+)?Z?)?|\d{8}(?:T?\d{6}Z?)?`)
	isoDateComponentPattern    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(?:T\d{2}:?\d{2}:?\d{2}(?:\.\d+)?Z?)?$`)
	compactDateComponentRegexp = regexp.MustCompile(`^\d{8}(?:T?\d{6}Z?)?$`)
	driveLikePathPattern       = regexp.MustCompile(`^[A-Za-z]:(?:$|/)`)
	schemeLikePathPattern      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)
	secretValuePattern         = regexp.MustCompile(`(?i)(authorization\s*:\s*[^\r\n]+|bearer\s+[A-Za-z0-9._~+/=-]{8,}|(?:access[-_]?token|api[-_]?key|pass(?:word|wd)|secret|token)\s*[=:]\s*\S+|github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+|sk-(?:proj-)?[A-Za-z0-9_-]{10,}|xox[abprs]-[A-Za-z0-9-]+|glpat-[A-Za-z0-9_-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)`)
	urlUserInfoPattern         = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@`)
	controlRunePattern         = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	shellControlTokenPattern   = regexp.MustCompile("(&&|\\|\\||[;&|<>`]|\\$\\(|\\r|\\n)")
)

const maxDiagnosticRunes = 512

type RedactionFixture struct {
	Input            string
	Name             string
	SensitiveNeedles []string
}

func ReportVisibleRedactionFixtures() []RedactionFixture {
	githubPAT := secretFixtureText("github", "_pat_", "abcdefghijklmnopqrstuvwxyz")
	githubToken := secretFixtureText("gh", "p_", "123456789012345678901234567890123456")
	openAIKey := secretFixtureText("sk", "-proj-", "abcdefghijklmnop")
	slackToken := secretFixtureText("xox", "b-", "1234567890-", "abcdefghijklmnop")
	gitLabToken := secretFixtureText("gl", "pat-", "abcdefghijklmnop")
	privateKeyHeader := secretFixtureText("-----BEGIN OPENSSH ", "PRIVATE KEY-----")
	jwtLike := secretFixtureText("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjMifQ", ".", "signature")
	return []RedactionFixture{
		{Name: "authorization_header", Input: "request failed: Authorization: Basic YWxpY2U6c2VjcmV0", SensitiveNeedles: []string{"Authorization", "Basic", "YWxpY2U6c2VjcmV0"}},
		{Name: "bearer_token", Input: "Bearer abcdefghijklmnopqrstuvwxyz", SensitiveNeedles: []string{"abcdefghijklmnopqrstuvwxyz"}},
		{Name: "api_key_label", Input: "api_key=abc123456789", SensitiveNeedles: []string{"abc123456789"}},
		{Name: "access_token_label", Input: "access-token=abcdefghijklmnopqrstuvwxyz", SensitiveNeedles: []string{"abcdefghijklmnopqrstuvwxyz"}},
		{Name: "password_label", Input: "passwd=abcdefghijklmnopqrstuvwxyz", SensitiveNeedles: []string{"abcdefghijklmnopqrstuvwxyz"}},
		{Name: "github_pat", Input: githubPAT, SensitiveNeedles: []string{githubPAT}},
		{Name: "github_ghp", Input: githubToken, SensitiveNeedles: []string{githubToken}},
		{Name: "openai_key", Input: openAIKey, SensitiveNeedles: []string{"abcdefghijklmnop"}},
		{Name: "slack_token", Input: slackToken, SensitiveNeedles: []string{"1234567890", "abcdefghijklmnop"}},
		{Name: "gitlab_token", Input: gitLabToken, SensitiveNeedles: []string{"abcdefghijklmnop"}},
		{Name: "url_credentials", Input: "https://user:password@example.test/repo.git", SensitiveNeedles: []string{"user:password"}},
		{Name: "private_key_header", Input: privateKeyHeader, SensitiveNeedles: []string{"PRIVATE KEY"}},
		{Name: "jwt_like", Input: jwtLike, SensitiveNeedles: []string{"eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjMifQ", "signature"}},
	}
}

func secretFixtureText(parts ...string) string {
	return strings.Join(parts, "")
}

func KnownKeys(record map[string]any, admitted []string, context string) error {
	admittedSet := map[string]struct{}{}
	for _, key := range admitted {
		admittedSet[key] = struct{}{}
	}
	unknown := []string{}
	for key := range record {
		if _, ok := admittedSet[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("%s has unsupported field(s): %s", context, strings.Join(diagnosticFieldLabels(unknown), ", "))
}

func RuleID(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || !ruleIDPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be stable rule identifier text", context)
	}
	if ContainsSecretLikeValue(value) {
		return "", fmt.Errorf("%s must not contain secret-like values", context)
	}
	if timestampLikePattern.MatchString(value) {
		return "", fmt.Errorf("%s must not contain timestamp-like identity components", context)
	}
	for _, component := range regexp.MustCompile(`[._:-]`).Split(value, -1) {
		if isoDateComponentPattern.MatchString(component) || compactDateComponentRegexp.MatchString(component) {
			return "", fmt.Errorf("%s must not contain timestamp-like identity components", context)
		}
	}
	return value, nil
}

func NonEmptyText(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s must be non-empty text", context)
	}
	value = strings.TrimSpace(value)
	if ContainsSecretLikeValue(value) {
		return "", fmt.Errorf("%s must not contain secret-like values", context)
	}
	return value, nil
}

func LowercaseSHA256(raw any, context string) (string, error) {
	value, err := NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if len(value) != 64 || strings.ToLower(value) != value || strings.Trim(value, "0123456789abcdef") != "" {
		return "", fmt.Errorf("%s must be lowercase sha256", context)
	}
	return value, nil
}

func ContainsSecretLikeValue(value string) bool {
	return ContainsSecretTokenLikeValue(value) || ContainsURLCredentialValue(value)
}

func ContainsSecretTokenLikeValue(value string) bool {
	return secretValuePattern.MatchString(value)
}

func ContainsURLCredentialValue(value string) bool {
	return urlUserInfoPattern.MatchString(value)
}

func RedactSecretLikeValue(value string) string {
	value = secretValuePattern.ReplaceAllString(value, "<redacted-secret-like-value>")
	return urlUserInfoPattern.ReplaceAllString(value, "<redacted-secret-like-value>")
}

func RedactDiagnosticValue(value string) string {
	value = RedactSecretLikeValue(value)
	value = redactControlRunes(value)
	runes := []rune(value)
	if len(runes) <= maxDiagnosticRunes {
		return value
	}
	return string(runes[:maxDiagnosticRunes]) + "...<truncated-diagnostic>"
}

func RedactStructuralText(value string) string {
	return redactControlRunes(RedactSecretLikeValue(value))
}

func redactControlRunes(value string) string {
	var builder strings.Builder
	redacting := false
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			if !redacting {
				builder.WriteString("<redacted-control-rune>")
				redacting = true
			}
			continue
		}
		redacting = false
		builder.WriteRune(character)
	}
	return builder.String()
}

func DisplayOnlyCommandText(raw any, context string) (string, error) {
	value, err := NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if shellControlTokenPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be display-only command text without shell control tokens", context)
	}
	return value, nil
}

func StructuredSelectorSourcePath(selector string, sourcePath string, context string) error {
	if !strings.Contains(selector, "::") {
		return nil
	}
	parts := strings.Split(selector, "::")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("%s must use repo/path::stable_anchor when it declares source identity", context)
	}
	selectorPath, err := SafeRepoRelativePath(parts[0], context+" source path")
	if err != nil {
		return err
	}
	if _, err := RuleID(parts[1], context+" anchor"); err != nil {
		return err
	}
	if selectorPath != sourcePath {
		return fmt.Errorf("%s sourcePath must match selector path: %s !== %s", context, sourcePath, selectorPath)
	}
	return nil
}

func diagnosticFieldLabels(values []string) []string {
	labels := make([]string, 0, len(values))
	redacted := 0
	for _, value := range values {
		if ContainsSecretLikeValue(value) || controlRunePattern.MatchString(value) || len(value) > 120 {
			redacted++
			labels = append(labels, fmt.Sprintf("<redacted-unsupported-field-%03d>", redacted))
			continue
		}
		labels = append(labels, value)
	}
	return labels
}

func NullableText(raw any, context string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := NonEmptyText(raw, context)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func TextArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		text, err := NonEmptyText(item, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	if !allowEmpty && len(result) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	return result, nil
}

func SortedText(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	sort.Strings(values)
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return values, nil
}

func SortedTextArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	return SortedText(values, context, allowEmpty)
}

func MergeNonClaims(required []string, caller []string, context string) ([]string, error) {
	values := make([]string, 0, len(required)+len(caller))
	for index, value := range required {
		text, err := NonEmptyText(value, fmt.Sprintf("%s required nonClaims[%d]", context, index))
		if err != nil {
			return nil, err
		}
		values = append(values, text)
	}
	for index, value := range caller {
		text, err := NonEmptyText(value, fmt.Sprintf("%s caller nonClaims[%d]", context, index))
		if err != nil {
			return nil, err
		}
		values = append(values, text)
	}
	sort.Strings(values)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("%s nonClaims must be non-empty", context)
	}
	return result, nil
}

func PreserveSortedText(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	for index := 0; index < len(values); index++ {
		if values[index] != sorted[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
		if index > 0 && values[index-1] == values[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return values, nil
}

func PreserveSortedTextArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	return PreserveSortedText(values, context, allowEmpty)
}

func SafeRepoRelativePath(value string, context string) (string, error) {
	if value == "" ||
		strings.HasPrefix(value, "/") ||
		strings.Contains(value, `\`) ||
		containsControlRune(value) ||
		ContainsSecretLikeValue(value) ||
		driveLikePathPattern.MatchString(value) ||
		schemeLikePathPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be a repository-relative POSIX path", context)
	}
	normalized := path.Clean(value)
	if normalized != value ||
		normalized == "." ||
		normalized == "./" ||
		normalized == ".." ||
		strings.HasPrefix(normalized, "../") ||
		strings.Contains(normalized, "/../") {
		return "", fmt.Errorf("%s must not escape the repository root", context)
	}
	return normalized, nil
}

func containsControlRune(value string) bool {
	for _, character := range value {
		if character < ' ' || character == 0x7f {
			return true
		}
	}
	return false
}

func PreserveSortedPathArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(values))
	for _, value := range values {
		pathValue, err := SafeRepoRelativePath(value, context)
		if err != nil {
			return nil, err
		}
		paths = append(paths, pathValue)
	}
	return PreserveSortedText(paths, context, allowEmpty)
}

func Enum(raw any, values map[string]struct{}, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of %s", context, SortedEnum(values))
	}
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s must be one of %s", context, SortedEnum(values))
	}
	return value, nil
}

func SortedEnum(values map[string]struct{}) string {
	names := make([]string, 0, len(values))
	for value := range values {
		names = append(names, value)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func Bool(raw any, context string) (bool, error) {
	value, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be boolean", context)
	}
	return value, nil
}

func PositiveInteger(raw any, context string) (int, error) {
	number, ok := raw.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s must be a positive integer", context)
	}
	value, err := number.Int64()
	if err != nil || value <= 0 || int64(int(value)) != value {
		return 0, fmt.Errorf("%s must be a positive integer", context)
	}
	return int(value), nil
}

func JSONNumberEquals(raw any, expected int64) bool {
	number, ok := raw.(json.Number)
	if !ok {
		return false
	}
	value, err := number.Int64()
	return err == nil && value == expected
}

func StringSliceToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func AnySliceToString(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}
