package secretjson

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestScanFindsSecretShapedValuesAndKeysWithoutEchoingKey(t *testing.T) {
	findings, err := Scan(map[string]any{
		"safe":         "Authorization: Bearer abcdefghijklmnop",
		"operatorNote": "api-key=abcdefghijklmnopqrstuvwxyz",
		"api_key=ghp_secretvalue": map[string]any{
			"child": "ok",
		},
		"passwd=zyxwvutsrqponmlkjihgfedcba":      "redacted",
		"https://user:password@example.test/key": "safe",
		"nested": []any{
			map[string]any{"url": "https://user:password@example.test/path"},
		},
	}, "evidence")
	if err != nil {
		t.Fatalf("Scan() error=%v", err)
	}

	want := []Finding{
		{Path: "evidence.nested[0].url", Kind: KindURLCredentials},
		{Path: "evidence.operatorNote", Kind: KindSecretShapedValue},
		{Path: "evidence.safe", Kind: KindSecretShapedValue},
		{Path: "evidence.{key:0}", Kind: KindSecretShapedKey},
		{Path: "evidence.{key:1}", Kind: KindURLCredentialsKey},
		{Path: "evidence.{key:4}", Kind: KindSecretShapedKey},
	}
	if len(findings) != len(want) {
		t.Fatalf("Scan() findings=%v, want %v", findings, want)
	}
	for index := range want {
		if findings[index] != want[index] {
			t.Fatalf("Scan()[%d]=%v, want %v", index, findings[index], want[index])
		}
	}
	for _, finding := range findings {
		if strings.Contains(finding.Path, "ghp_secretvalue") || strings.Contains(finding.Path, "api_key") || strings.Contains(finding.Path, "zyxwvutsrqponmlkjihgfedcba") || strings.Contains(finding.Path, "passwd") {
			t.Fatalf("Scan() leaked secret-shaped key in path: %v", findings)
		}
	}
}

func TestScanRejectsNonJSONValuesAndUnsafeRoot(t *testing.T) {
	for _, test := range []struct {
		name string
		root string
		raw  any
	}{
		{name: "empty root", root: "", raw: map[string]any{}},
		{name: "secret root", root: "ghp_secretvalue", raw: map[string]any{}},
		{name: "non json", root: "evidence", raw: strings.Builder{}},
		{name: "empty key", root: "evidence", raw: map[string]any{"": "value"}},
		{name: "nul key", root: "evidence", raw: map[string]any{"bad\x00key": "value"}},
		{name: "control key", root: "evidence", raw: map[string]any{"bad\nkey": "value"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Scan(test.raw, test.root); err == nil {
				t.Fatal("Scan() error=nil, want rejection")
			}
		})
	}
}

func TestScanAdmitsJSONScalarKinds(t *testing.T) {
	if findings, err := Scan(map[string]any{
		"null":   nil,
		"bool":   true,
		"int":    1,
		"int64":  int64(2),
		"float":  3.5,
		"number": json.Number("4"),
	}, "evidence"); err != nil || len(findings) != 0 {
		t.Fatalf("Scan() findings=%v error=%v, want no findings", findings, err)
	}
}
