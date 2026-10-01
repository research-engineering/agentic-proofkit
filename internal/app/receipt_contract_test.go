package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// Currentness/trust observations were captured on 5f24adf; receipt/producer
// observations on e9df147, before their structural projections existed.
// Expected reports are not produced by the current builder.
func TestReceiptCLIHistoricalWireAndTransports(t *testing.T) {
	for _, family := range []struct {
		command, file string
		count         int
	}{
		{"receipt-currentness-scope", "receipt-currentness-native-observations.json", 4},
		{"receipt-trust-class", "receipt-trust-native-observations.json", 4},
		{"proof-receipt-admission", "proof-receipt-native-observations.json", 7},
		{"receipt-producer-admission", "receipt-producer-native-observations.json", 7},
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
		if err := json.Unmarshal(data, &rows); err != nil || len(rows) != family.count {
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
	const largeControlToken = "9007199254740993"
	controlOutputs := map[string][]byte{}
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
				if code != 0 || stderr.Len() != 0 || !hasExactReceiptTrustRanks(stdout.Bytes(), json.Number(token)) {
					t.Fatalf("exact rank was lost: %d %s %s", code, stdout.String(), stderr.String())
				}
				if token == "1" || token == largeControlToken {
					controlOutputs[token] = bytes.Clone(stdout.Bytes())
				}
			} else if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "rank") {
				t.Fatalf("invalid rank did not fail at admission: %d %s %s", code, stdout.String(), stderr.String())
			}
		})
	}
	for _, controlToken := range []string{"1", largeControlToken} {
		controlOutput := controlOutputs[controlToken]
		if !hasExactReceiptTrustRanks(controlOutput, json.Number(controlToken)) {
			t.Fatal("counterfeit controls require a native exact-number positive")
		}
		for _, site := range []string{"report", "rule"} {
			for _, field := range []string{"actualTrustRank", "minimumTrustRank"} {
				for _, mutation := range []string{"suffix", "neighbor", "noncanonical", "quoted", "missing", "null"} {
					t.Run(controlToken+"/"+site+"/"+field+"/"+mutation, func(t *testing.T) {
						value, err := admission.DecodeJSON(bytes.NewReader(controlOutput), maxInputBytes)
						if err != nil {
							t.Fatal(err)
						}
						observation := value.(map[string]any)["diagnostics"].([]any)[1].(map[string]any)["value"].([]any)[0].(map[string]any)
						if site == "rule" {
							observation = value.(map[string]any)["ruleResults"].([]any)[0].(map[string]any)["diagnostics"].([]any)[0].(map[string]any)["value"].(map[string]any)
						}
						switch mutation {
						case "suffix":
							observation[field] = json.Number(controlToken + "0")
						case "neighbor":
							observation[field] = json.Number(map[string]string{"1": "2", largeControlToken: "9007199254740992"}[controlToken])
						case "noncanonical":
							observation[field] = json.Number(controlToken + ".0")
						case "quoted":
							observation[field] = controlToken
						case "missing":
							delete(observation, field)
						case "null":
							observation[field] = nil
						}
						encoded, err := json.MarshalIndent(value, "", "  ")
						if err != nil {
							t.Fatal(err)
						}
						if mutation == "suffix" && !strings.Contains(string(encoded), `"`+field+`": `+controlToken) {
							t.Fatal("counterfeit no longer distinguishes substring from exact equality")
						}
						if hasExactReceiptTrustRanks(encoded, json.Number(controlToken)) {
							t.Fatal("counterfeit rank satisfied the exact numeric observer")
						}
					})
				}
			}
		}
	}
}

func hasExactReceiptTrustRanks(raw []byte, expected json.Number) bool {
	value, err := admission.DecodeJSON(bytes.NewReader(raw), maxInputBytes)
	if err != nil {
		return false
	}
	for _, prefix := range []string{"/diagnostics/1/value/0/", "/ruleResults/0/diagnostics/0/value/"} {
		for _, field := range []string{"actualTrustRank", "minimumTrustRank"} {
			actual, err := jsonpointer.Select(value, prefix+field)
			if err != nil || actual != expected {
				return false
			}
		}
	}
	return true
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
