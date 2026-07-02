package secretjson

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

type Kind string

const (
	KindSecretShapedValue Kind = "secret_shaped_value"
	KindSecretShapedKey   Kind = "secret_shaped_key"
	KindURLCredentials    Kind = "url_credentials"
	KindURLCredentialsKey Kind = "url_credentials_key"
)

var rootPathPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:\-[\]]*$`)

type Finding struct {
	Path string
	Kind Kind
}

func Scan(value any, rootPath string) ([]Finding, error) {
	rootPath = strings.TrimSpace(rootPath)
	if rootPath == "" || len(rootPath) > 80 || !rootPathPattern.MatchString(rootPath) || admit.ContainsSecretLikeValue(rootPath) {
		return nil, fmt.Errorf("secret-shaped JSON scan rootPath must be stable path label text")
	}

	findings := []Finding{}
	if err := collect(value, rootPath, &findings); err != nil {
		return nil, err
	}
	return stableUnique(findings), nil
}

func collect(value any, path string, findings *[]Finding) error {
	switch typed := value.(type) {
	case nil, bool, string:
		if text, ok := typed.(string); ok {
			collectText(text, path, false, findings)
		}
		return nil
	case float64, int, int64, json.Number:
		return nil
	case fmt.Stringer:
		return fmt.Errorf("%s must be JSON-serializable", path)
	case []any:
		for index, item := range typed {
			if err := collect(item, fmt.Sprintf("%s[%d]", path, index), findings); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for keyIndex, key := range keys {
			if key == "" || containsControlRune(key) {
				return fmt.Errorf("%s.{key:%d} object key must be non-empty text", path, keyIndex)
			}
			keyPath := fmt.Sprintf("%s.{key:%d}", path, keyIndex)
			before := len(*findings)
			collectText(key, keyPath, true, findings)
			childPath := path + "." + key
			if len(*findings) != before {
				childPath = keyPath + ".value"
			}
			if err := collect(typed[key], childPath, findings); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%s must be JSON-serializable", path)
	}
}

func containsControlRune(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func collectText(value string, path string, key bool, findings *[]Finding) {
	if admit.ContainsSecretTokenLikeValue(value) {
		kind := KindSecretShapedValue
		if key {
			kind = KindSecretShapedKey
		}
		*findings = append(*findings, Finding{Path: path, Kind: kind})
	}
	if admit.ContainsURLCredentialValue(value) {
		kind := KindURLCredentials
		if key {
			kind = KindURLCredentialsKey
		}
		*findings = append(*findings, Finding{Path: path, Kind: kind})
	}
}

func stableUnique(findings []Finding) []Finding {
	sort.Slice(findings, func(left int, right int) bool {
		if findings[left].Path == findings[right].Path {
			return findings[left].Kind < findings[right].Kind
		}
		return findings[left].Path < findings[right].Path
	})
	result := findings[:0]
	var previous Finding
	for index, finding := range findings {
		if index == 0 || finding != previous {
			result = append(result, finding)
		}
		previous = finding
	}
	return result
}
