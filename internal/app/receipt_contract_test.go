package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// These observations were captured on 5f24adf before receipt structural
// projections existed. Expected reports are not produced by the current builder.
func TestReceiptCLIHistoricalWireAndTransports(t *testing.T) {
	for _, family := range []struct{ command, file string }{
		{"receipt-currentness-scope", "receipt-currentness-native-observations.json"},
		{"receipt-trust-class", "receipt-trust-native-observations.json"},
	} {
		data, err := os.ReadFile(filepath.Join("testdata", family.file))
		if err != nil {
			t.Fatal(err)
		}
		var rows []struct {
			Case     string          `json:"case"`
			Input    json.RawMessage `json:"input"`
			Output   json.RawMessage `json:"output"`
			ExitCode int             `json:"exitCode"`
		}
		if err := json.Unmarshal(data, &rows); err != nil || len(rows) != 4 {
			t.Fatalf("invalid observation inventory: %v", err)
		}
		for _, row := range rows {
			t.Run(family.command+"/"+row.Case, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "input.json")
				if err := os.WriteFile(path, row.Input, 0600); err != nil {
					t.Fatal(err)
				}
				for _, transport := range []struct {
					name, stdin string
					args        []string
				}{
					{"stdin", string(row.Input), []string{"--input", "-"}},
					{"file", "", []string{"--input", path}},
					{"pointer", `{"payload":` + string(row.Input) + `}`, []string{"--input", "-", "--input-pointer", "/payload"}},
				} {
					t.Run(transport.name, func(t *testing.T) {
						var stdout, stderr bytes.Buffer
						code := Run(t.Context(), append([]string{family.command}, transport.args...), strings.NewReader(transport.stdin), &stdout, &stderr)
						if code != row.ExitCode || stderr.Len() != 0 {
							t.Fatalf("exit=%d stderr=%s", code, stderr.String())
						}
						if !bytes.Equal(canonicalReceiptJSON(t, stdout.Bytes()), canonicalReceiptJSON(t, row.Output)) {
							t.Fatalf("native wire changed from pre-schema observation: %s", stdout.String())
						}
					})
				}
			})
		}
	}
}

func TestReceiptTrustCLIExactIntegerTokens(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "receipt-trust-native-observations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct{ Input json.RawMessage }
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"1", "9007199254740993", "9223372036854775807", "0", "-1", "1.0", "1e0", "9223372036854775808"} {
		t.Run(token, func(t *testing.T) {
			decoder := json.NewDecoder(bytes.NewReader(rows[0].Input))
			decoder.UseNumber()
			var input map[string]any
			if err := decoder.Decode(&input); err != nil {
				t.Fatal(err)
			}
			input["trustClasses"].([]any)[0].(map[string]any)["rank"] = json.Number(token)
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := Run(t.Context(), []string{"receipt-trust-class", "--input", "-"}, bytes.NewReader(encoded), &stdout, &stderr)
			valid := token == "1" || token == "9007199254740993" || token == "9223372036854775807"
			if valid {
				if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"actualTrustRank": `+token) {
					t.Fatalf("exact rank was lost: %d %s %s", code, stdout.String(), stderr.String())
				}
			} else if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "rank") {
				t.Fatalf("invalid rank did not fail at admission: %d %s %s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func canonicalReceiptJSON(t *testing.T, data []byte) []byte {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
