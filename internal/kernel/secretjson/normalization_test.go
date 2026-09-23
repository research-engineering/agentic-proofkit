package secretjson

import (
	"reflect"
	"strings"
	"testing"
)

func TestScanUsesCanonicalNormalizationWithoutMergingFindingKinds(t *testing.T) {
	for _, test := range []struct {
		text      string
		valueKind Kind
		keyKind   Kind
	}{
		{"api_\u200bkey=synthetic-fixture-value", KindSecretShapedValue, KindSecretShapedKey},
		{"https:\u200b//user:synthetic-fixture-value@example.test/path", KindURLCredentials, KindURLCredentialsKey},
		{`"password": "synthetic-fixture-value"`, KindSecretShapedValue, KindSecretShapedKey},
	} {
		value, err := Scan(map[string]any{"note": test.text}, "evidence")
		if err != nil || !reflect.DeepEqual(value, []Finding{{Path: "evidence.note", Kind: test.valueKind}}) {
			t.Fatalf("value classification = %v, error = %v", value, err)
		}
		key, err := Scan(map[string]any{test.text: map[string]any{"safe": true}}, "evidence")
		if err != nil || !reflect.DeepEqual(key, []Finding{{Path: "evidence.{key:0}", Kind: test.keyKind}}) {
			t.Fatalf("key classification = %v, error = %v", key, err)
		}
		for _, finding := range append(value, key...) {
			if strings.Contains(finding.Path, "synthetic-fixture-value") {
				t.Fatal("finding disclosed caller text")
			}
		}
	}
	if findings, err := Scan(map[string]any{"passwordLabel": "A caf\u00e9 label.", "token": nil}, "evidence"); err != nil || len(findings) != 0 {
		t.Fatalf("safe Unicode/key-only control = %v, error = %v", findings, err)
	}
}
