package admit

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/unicodepolicy"
)

const (
	secretWhitespaceClassSource      = `\t\n\v\f\r \x85\p{Zs}\p{Zl}\p{Zp}`
	secretWhitespacePatternSource    = `(?:[` + secretWhitespaceClassSource + `]|\\+[ntrfv]|\\+u(?:000[9a-d]|0020|0085|00a0|202[89]))`
	secretNonWhitespacePatternSource = `[^` + secretWhitespaceClassSource + `]`
	secretKeyQuotePatternSource      = `(?:\\*["'])?`
	secretContextPatternSource       = `authorization` + secretKeyQuotePatternSource + secretWhitespacePatternSource + `*:` + secretWhitespacePatternSource + `*[^\r\n]+|bearer` + secretWhitespacePatternSource + `+[A-Za-z0-9._~+/=-]{8,}|(?:access[-_]?token|api[-_]?key|pass(?:word|wd)|secret|token)` + secretKeyQuotePatternSource + secretWhitespacePatternSource + `*[=:]` + secretWhitespacePatternSource + `*` + secretNonWhitespacePatternSource + `+|-----BEGIN [A-Z ]*PRIVATE KEY-----`
	secretSharedTokenPatternSource   = `github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+|xox[abprs]-[A-Za-z0-9-]+|glpat-[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
	secretScalarTokenPatternSource   = secretSharedTokenPatternSource + `|sk-(?:proj-)?[A-Za-z0-9_-]{10,}`
	secretPathTokenPatternSource     = secretSharedTokenPatternSource + `|sk-(?:proj-[A-Za-z0-9_-]{10,}|[A-Za-z0-9_-]{16,})`
)

const RuleIDPatternBody = `[A-Za-z][A-Za-z0-9_]*(?:[._:-][A-Za-z0-9_]+)*`

var (
	ruleIDPattern              = regexp.MustCompile(`^` + RuleIDPatternBody + `$`)
	ruleIDSeparatorPattern     = regexp.MustCompile(`[._:-]`)
	timestampLikePattern       = regexp.MustCompile(`\d{4}-\d{2}-\d{2}(?:T\d{2}:?\d{2}:?\d{2}(?:\.\d+)?Z?)?|\d{8}(?:T?\d{6}Z?)?`)
	isoDateComponentPattern    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(?:T\d{2}:?\d{2}:?\d{2}(?:\.\d+)?Z?)?$`)
	compactDateComponentRegexp = regexp.MustCompile(`^\d{8}(?:T?\d{6}Z?)?$`)
	driveLikePathPattern       = regexp.MustCompile(`^[A-Za-z]:(?:$|/)`)
	schemeLikePathPattern      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)
	secretValuePattern         = regexp.MustCompile(`(?i)(?:` + secretContextPatternSource + `|` + secretScalarTokenPatternSource + `)`)
	secretPathContextPattern   = regexp.MustCompile(`(?i)(?:` + secretContextPatternSource + `)`)
	secretPathTokenPattern     = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])(?:` + secretPathTokenPatternSource + `)(?:$|[^A-Za-z0-9_])`)
	urlUserInfoPattern         = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^/` + secretWhitespaceClassSource + `:@]+:[^/` + secretWhitespaceClassSource + `@]+@`)
	controlRunePattern         = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	shellControlTokenPattern   = regexp.MustCompile("(&&|\\|\\||[;&|<>`]|\\$\\(|\\r|\\n)")
)

const (
	maxDiagnosticRunes = 512
	maxRuleIDBytes     = 256
	redactedValueLabel = "<redacted-diagnostic-value>"
)

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
		{Name: "authorization_double_escaped_json_key", Input: `authorization\\": "Basic synthetic-fixture-value"`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "authorization_json_escaped_unicode_space", Input: `\"Authorization\"\u202f:"Basic synthetic-fixture-value"`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "bearer_token", Input: "Bearer abcdefghijklmnopqrstuvwxyz", SensitiveNeedles: []string{"abcdefghijklmnopqrstuvwxyz"}},
		{Name: "api_key_label", Input: "api_key=abc123456789", SensitiveNeedles: []string{"abc123456789"}},
		{Name: "api_key_unicode_whitespace", Input: "api_key\u00a0=abc123456789", SensitiveNeedles: []string{"abc123456789"}},
		{Name: "api_key_control_split", Input: "api_\u200bkey=abc123456789", SensitiveNeedles: []string{"abc123456789"}},
		{Name: "api_key_json_escaped_control_split", Input: `api_\tkey=synthetic-fixture-value`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "api_key_double_json_escaped_control_split", Input: `api_\\tkey=synthetic-fixture-value`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "api_key_escaped_unicode_letter", Input: `api_k\\u0065y=synthetic-fixture-value`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "api_key_escaped_supplementary_control", Input: `api_\\uDB40\\uDC01key=synthetic-fixture-value`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "api_key_escaped_composed_controls", Input: `api_\\u200b\\uDB40\\uDC01key=synthetic-fixture-value`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "api_key_escaped_letter_and_control", Input: `api_\\u006b\\uDB40\\uDC01ey=synthetic-fixture-value`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "access_token_label", Input: "access-token=abcdefghijklmnopqrstuvwxyz", SensitiveNeedles: []string{"abcdefghijklmnopqrstuvwxyz"}},
		{Name: "password_label", Input: "passwd=abcdefghijklmnopqrstuvwxyz", SensitiveNeedles: []string{"abcdefghijklmnopqrstuvwxyz"}},
		{Name: "password_quoted_json_key", Input: `"password": "synthetic-fixture-value"`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "token_escaped_json_key", Input: `\"token\": \"synthetic-fixture-value\"`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "password_double_escaped_json_key", Input: `password\\": "synthetic-fixture-value"`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "password_triple_escaped_json_key", Input: `password\\\": "synthetic-fixture-value"`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "password_json_escaped_newline", Input: `"password"\n: "synthetic-fixture-value"`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "password_double_json_escaped_newline", Input: `"password"\\n: "synthetic-fixture-value"`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
		{Name: "password_triple_json_escaped_newline", Input: `"password"\\\n: "synthetic-fixture-value"`, SensitiveNeedles: []string{"synthetic-fixture-value"}},
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
	if !ok {
		return "", fmt.Errorf("%s must be stable rule identifier text", context)
	}
	if len(value) > maxRuleIDBytes {
		return "", fmt.Errorf("%s exceeds the %d-byte stable identifier limit", context, maxRuleIDBytes)
	}
	if !ruleIDPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be stable rule identifier text", context)
	}
	if ContainsSecretLikeValue(value) {
		return "", fmt.Errorf("%s must not contain secret-like values", context)
	}
	if timestampLikePattern.MatchString(value) {
		return "", fmt.Errorf("%s must not contain timestamp-like identity components", context)
	}
	for _, component := range ruleIDSeparatorPattern.Split(value, -1) {
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

func SHA256Ref(raw any, context string) (string, error) {
	value, err := NonEmptyText(raw, context)
	if err != nil || !strings.HasPrefix(value, "sha256:") {
		return "", fmt.Errorf("%s must be a sha256 digest reference", context)
	}
	digest, err := LowercaseSHA256(strings.TrimPrefix(value, "sha256:"), context)
	if err != nil {
		return "", err
	}
	return "sha256:" + digest, nil
}

func SHA256HexRef(raw any, context string) (string, error) {
	digest, err := LowercaseSHA256(raw, context)
	if err != nil {
		return "", err
	}
	return "sha256:" + digest, nil
}

func ContainsSecretLikeValue(value string) bool {
	return matchesNormalizedSecret(value, func(text string) bool {
		return secretValuePattern.MatchString(text) || urlUserInfoPattern.MatchString(text)
	})
}

func ContainsReportVisibleUnsafeValue(value string) bool {
	return unicodepolicy.ContainsUnsafeScalar(value) || ContainsSecretLikeValue(value)
}

func ContainsSecretLikePathValue(value string) bool {
	return matchesNormalizedSecret(value, func(text string) bool {
		return urlUserInfoPattern.MatchString(text) || secretPathContextPattern.MatchString(text) || secretPathTokenPattern.MatchString(text)
	})
}

func ContainsSecretTokenLikeValue(value string) bool {
	return matchesNormalizedSecret(value, secretValuePattern.MatchString)
}

func ContainsURLCredentialValue(value string) bool {
	return matchesNormalizedSecret(value, urlUserInfoPattern.MatchString)
}

// SecretLikeValuePatternSources projects the shared, case-insensitive Unicode
// pattern bodies for generated adapters. Normalization remains a separate step.
func SecretLikeValuePatternSources() []string {
	return []string{secretContextPatternSource + "|" + secretScalarTokenPatternSource, urlUserInfoPattern.String()}
}

func matchesNormalizedSecret(value string, matches func(string) bool) bool {
	for _, candidate := range []string{value, decodeEscapedSecretText(value)} {
		if matches(candidate) {
			return true
		}
		withoutUnsafe := withoutUnsafeScalars(candidate)
		if withoutUnsafe != candidate && matches(withoutUnsafe) {
			return true
		}
	}
	return false
}

func decodeEscapedSecretText(value string) string {
	var result strings.Builder
	result.Grow(len(value))
	for index := 0; index < len(value); {
		if value[index] != '\\' {
			result.WriteByte(value[index])
			index++
			continue
		}
		start := index
		for index < len(value) && value[index] == '\\' {
			index++
		}
		if index >= len(value) {
			result.WriteString(value[start:index])
			break
		}
		if value[index] == 'u' && hasSecretUnicodeUnit(value, index) {
			first := decodeSecretUnicodeUnit(value[index+1 : index+5])
			next := index + 5
			if first >= 0xd800 && first <= 0xdbff {
				secondStart := next
				for next < len(value) && value[next] == '\\' {
					next++
				}
				if next > secondStart && next < len(value) && value[next] == 'u' && hasSecretUnicodeUnit(value, next) {
					second := decodeSecretUnicodeUnit(value[next+1 : next+5])
					if second >= 0xdc00 && second <= 0xdfff {
						result.WriteRune(utf16.DecodeRune(first, second))
						index = next + 5
						continue
					}
				}
			}
			result.WriteString(decodeSecretUnicodeScalar(first, value[start:index+5]))
			index += 5
			continue
		}
		switch value[index] {
		case 'n':
			result.WriteByte('\n')
		case 't':
			result.WriteByte('\t')
		case 'r':
			result.WriteByte('\r')
		case 'f':
			result.WriteByte('\f')
		case 'v':
			result.WriteByte('\v')
		case 'b':
			result.WriteByte('\b')
		case '/', '"':
			result.WriteByte(value[index])
		default:
			result.WriteString(value[start:index])
			continue
		}
		index++
	}
	return result.String()
}

func hasSecretUnicodeUnit(value string, index int) bool {
	if index+5 > len(value) || value[index] != 'u' {
		return false
	}
	for _, digit := range value[index+1 : index+5] {
		if !(digit >= '0' && digit <= '9' || digit >= 'a' && digit <= 'f' || digit >= 'A' && digit <= 'F') {
			return false
		}
	}
	return true
}

func decodeSecretUnicodeUnit(hex string) rune {
	value, _ := strconv.ParseUint(hex, 16, 16)
	return rune(value)
}

func decodeSecretUnicodeScalar(value rune, original string) string {
	if value >= 0xd800 && value <= 0xdfff {
		return original
	}
	return string(value)
}

func RedactSecretLikeValue(value string) string {
	if ContainsSecretLikeValue(value) {
		return redactedValueLabel
	}
	return value
}

func RedactDiagnosticValue(value string) string {
	if !unicodepolicy.ValidScalarString(value) || ContainsReportVisibleUnsafeValue(value) {
		return redactedValueLabel
	}
	runes := []rune(value)
	if len(runes) <= maxDiagnosticRunes {
		return value
	}
	return string(runes[:maxDiagnosticRunes]) + "...<truncated-diagnostic>"
}

func RedactStructuralText(value string) string {
	if !unicodepolicy.ValidScalarString(value) || unicodepolicy.ContainsUnsafeScalar(value) || ContainsSecretLikeValue(value) {
		return redactedValueLabel
	}
	return value
}

func withoutUnsafeScalars(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if !unicodepolicy.IsUnsafeScalar(character) {
			builder.WriteRune(character)
		}
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

func NormalizeSortedText(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	normalized := make([]string, 0, len(values))
	for index, value := range values {
		admitted, err := NonEmptyText(value, fmt.Sprintf("%s[%d]", context, index))
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, admitted)
	}
	sort.Strings(normalized)
	for index := 1; index < len(normalized); index++ {
		if normalized[index-1] == normalized[index] {
			return nil, fmt.Errorf("%s must be unique", context)
		}
	}
	return normalized, nil
}

func NormalizeSortedTextArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := TextArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	return NormalizeSortedText(values, context, allowEmpty)
}

func NormalizeSortedPaths(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	paths := make([]string, 0, len(values))
	for index, value := range values {
		pathValue, err := SafeRepoRelativePath(value, fmt.Sprintf("%s[%d]", context, index))
		if err != nil {
			return nil, err
		}
		paths = append(paths, pathValue)
	}
	sort.Strings(paths)
	for index := 1; index < len(paths); index++ {
		if paths[index-1] == paths[index] {
			return nil, fmt.Errorf("%s must be unique", context)
		}
	}
	return paths, nil
}

func NormalizeSortedPathArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := pathArrayValues(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	return NormalizeSortedPaths(values, context, allowEmpty)
}

func SortedText(values []string, context string, allowEmpty bool) ([]string, error) {
	return NormalizeSortedText(values, context, allowEmpty)
}

func SortedTextArray(raw any, context string, allowEmpty bool) ([]string, error) {
	return NormalizeSortedTextArray(raw, context, allowEmpty)
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
	canonical := make([]string, 0, len(values))
	for index, value := range values {
		admitted, err := NonEmptyText(value, fmt.Sprintf("%s[%d]", context, index))
		if err != nil {
			return nil, err
		}
		if admitted != value {
			return nil, fmt.Errorf("%s must contain canonical non-empty text", context)
		}
		canonical = append(canonical, admitted)
	}
	return preserveSortedCanonical(canonical, context)
}

func preserveSortedCanonical(canonical []string, context string) ([]string, error) {
	sorted := append([]string{}, canonical...)
	sort.Strings(sorted)
	for index := 0; index < len(canonical); index++ {
		if canonical[index] != sorted[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
		if index > 0 && canonical[index-1] == canonical[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return canonical, nil
}

func PreserveSortedTextArray(raw any, context string, allowEmpty bool) ([]string, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	values := make([]string, len(items))
	for index, item := range items {
		value, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be text", context, index)
		}
		values[index] = value
	}
	return PreserveSortedText(values, context, allowEmpty)
}

func SafeRepoRelativePath(value string, context string) (string, error) {
	if value == "" ||
		strings.HasPrefix(value, "/") ||
		strings.Contains(value, `\`) ||
		containsControlRune(value) ||
		ContainsSecretLikePathValue(value) ||
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
	values, err := pathArrayValues(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	return PreserveSortedPaths(values, context, allowEmpty)
}

func pathArrayValues(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	for index, item := range values {
		value, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be a repository-relative POSIX path", context, index)
		}
		result = append(result, value)
	}
	if !allowEmpty && len(result) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	return result, nil
}

func PreserveSortedPaths(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	paths := make([]string, 0, len(values))
	for index, value := range values {
		pathValue, err := SafeRepoRelativePath(value, fmt.Sprintf("%s[%d]", context, index))
		if err != nil {
			return nil, err
		}
		if pathValue != value {
			return nil, fmt.Errorf("%s must contain canonical repository-relative POSIX paths", context)
		}
		paths = append(paths, pathValue)
	}
	return preserveSortedCanonical(paths, context)
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
	value, err := CanonicalInteger(raw, context)
	if err != nil || value <= 0 || int64(int(value)) != value {
		return 0, fmt.Errorf("%s must be a positive integer", context)
	}
	return int(value), nil
}

func JSONNumberEquals(raw any, expected int64) bool {
	value, err := CanonicalInteger(raw, "JSON integer")
	return err == nil && value == expected
}

func CanonicalInteger(raw any, context string) (int64, error) {
	number, ok := raw.(json.Number)
	if !ok || !canonicalIntegerLexeme(number.String()) {
		return 0, fmt.Errorf("%s must be a canonical JSON integer", context)
	}
	value, err := number.Int64()
	if err != nil {
		return 0, fmt.Errorf("%s must be a canonical JSON integer", context)
	}
	return value, nil
}

func canonicalIntegerLexeme(value string) bool {
	if value == "0" {
		return true
	}
	start := 0
	if strings.HasPrefix(value, "-") {
		start = 1
	}
	if start == len(value) || value[start] < '1' || value[start] > '9' {
		return false
	}
	for index := start + 1; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
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
