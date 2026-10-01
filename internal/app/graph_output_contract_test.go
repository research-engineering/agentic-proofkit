package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementgraph"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessschedulerplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestGraphOutputContractMatchesNativeOwner(t *testing.T) {
	assertSourceStructure(t, "requirement-traceability-graph", "output", "proofkit.requirement-traceability-graph.output.v1.json-schema", requirementgraph.OutputStructure())
	t.Run("exact numeric normalization", func(t *testing.T) {
		for _, token := range []string{"0", "-0", "1.0", "1e0", "9007199254740993", "9007199254740995", "9223372036854775807", "9223372036854775808"} {
			if value := canonicalJSONValue(t, json.Number(token)); value != json.Number(token) {
				t.Fatalf("numeric token %s changed to %v", token, value)
			}
		}
		for _, tokens := range [][2]string{{"9007199254740992", "9007199254740993"}, {"9223372036854775807", "9223372036854775808"}} {
			left := canonicalJSONValue(t, map[string]any{"maximum": json.Number(tokens[0])})
			right := canonicalJSONValue(t, map[string]any{"maximum": json.Number(tokens[1])})
			if reflect.DeepEqual(left, right) {
				t.Fatal("schema normalization collapsed adjacent integers")
			}
		}
		if !reflect.DeepEqual(canonicalJSONValue(t, map[string]any{"maximum": 1}), canonicalJSONValue(t, map[string]any{"maximum": json.Number("1")})) {
			t.Fatal("equivalent integer representations differ after normalization")
		}
	})
}

func TestGraphSchemaWitnessPlanClosure(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "proofkit", "witness-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	decode := func() map[string]any {
		t.Helper()
		value, err := admission.DecodeJSON(bytes.NewReader(data), maxInputBytes)
		if err != nil {
			t.Fatal(err)
		}
		return value.(map[string]any)
	}
	baseline := decode()
	count := 0
	for _, raw := range baseline["commands"].([]any) {
		command := raw.(map[string]any)
		if command["id"] != "proofkit.graph-contract-check" {
			continue
		}
		count++
		if command["parallelGroup"] != "graph-contract" || command["networkPolicy"] != "none" || command["credentialClass"] != "none" || command["cachePolicy"] != "disabled" || !slices.Equal(stringsFromAny(command["argv"].([]any)), []string{"npm", "run", "graph-contract:check"}) {
			t.Fatal("graph witness execution declaration drifted")
		}
	}
	if count != 1 {
		t.Fatal("graph command must be uniquely declared")
	}
	result, exit, err := witnessschedulerplan.Build(baseline)
	if err != nil || exit != 0 || result.State != "passed" {
		t.Fatal("current graph witness plan is not owner-admitted")
	}
	for _, mutation := range []string{"missing-group", "missing-policy"} {
		t.Run(mutation, func(t *testing.T) {
			candidate := decode()
			if mutation == "missing-group" {
				vocabulary := candidate["vocabulary"].(map[string]any)
				groups := vocabulary["parallelGroups"].([]any)
				vocabulary["parallelGroups"] = slices.DeleteFunc(groups, func(raw any) bool { return raw == "graph-contract" })
			} else {
				policies := candidate["policies"].([]any)
				candidate["policies"] = slices.DeleteFunc(policies, func(raw any) bool { return raw.(map[string]any)["commandId"] == "proofkit.graph-contract-check" })
			}
			encoded, err := stablejson.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := Run(t.Context(), []string{"witness-scheduler-plan", "--input", "-"}, bytes.NewReader(encoded), &stdout, &stderr)
			if code != 1 {
				t.Fatal("witness closure mutation survived the whole CLI")
			}
			if mutation == "missing-group" && (stdout.Len() != 0 || stderr.Len() == 0) {
				t.Fatal("group failure must remain admission refusal")
			}
			if mutation == "missing-policy" {
				value, err := admission.DecodeJSON(bytes.NewReader(stdout.Bytes()), maxInputBytes)
				if err != nil || stderr.Len() != 0 || value.(map[string]any)["state"] != "failed" {
					t.Fatal("policy failure must remain an admitted failed report")
				}
			}
		})
	}
}

func TestGraphCLIHistoricalCarriersAndExactIntegerTransports(t *testing.T) {
	data, err := os.ReadFile("testdata/graph-native-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Case          string
		Input, Output json.RawMessage
	}
	if err := json.Unmarshal(data, &rows); err != nil || len(rows) != 8 {
		t.Fatalf("invalid graph carrier inventory: %v", err)
	}
	for _, row := range rows {
		t.Run(row.Case, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(path, row.Input, 0600); err != nil {
				t.Fatal(err)
			}
			for _, transport := range []struct {
				name, input string
				args        []string
			}{
				{"stdin", string(row.Input), []string{"--input", "-"}},
				{"file", "", []string{"--input", path}},
				{"pointer", `{"payload":` + string(row.Input) + `}`, []string{"--input", "-", "--input-pointer", "/payload"}},
			} {
				for _, layout := range []string{"pretty", "compact"} {
					t.Run(transport.name+"/"+layout, func(t *testing.T) {
						args := append([]string{"--json-layout", layout, "requirement-traceability-graph"}, transport.args...)
						var stdout, stderr bytes.Buffer
						code := Run(t.Context(), args, strings.NewReader(transport.input), &stdout, &stderr)
						if code != 0 || stderr.Len() != 0 {
							t.Fatalf("native graph CLI failed: exit=%d stderr=%s", code, stderr.String())
						}
						actual, err := admission.DecodeJSON(bytes.NewReader(stdout.Bytes()), maxInputBytes)
						if err != nil {
							t.Fatal(err)
						}
						expected, err := admission.DecodeJSON(bytes.NewReader(row.Output), maxInputBytes)
						if err != nil {
							t.Fatal(err)
						}
						actualBytes, err := stablejson.Marshal(actual)
						if err != nil {
							t.Fatal(err)
						}
						expectedBytes, err := stablejson.Marshal(expected)
						if err != nil || !bytes.Equal(actualBytes, expectedBytes) {
							t.Fatal("predecessor graph wire or exact integer token changed")
						}
						if _, err := requirementgraph.AdmitOutput(actual, actual.(map[string]any)["snapshotId"].(string)); err != nil {
							t.Fatal(err)
						}
						if row.Case == "int64-range" {
							found := false
							for _, raw := range actual.(map[string]any)["nodes"].([]any) {
								node := raw.(map[string]any)
								if node["kind"] == "source_range" {
									found = node["byteStart"] == json.Number("9007199254740993") && node["byteEnd"] == json.Number("9007199254740995")
								}
							}
							if !found {
								t.Fatal("exact int64 witness lost its unsafe-JS integer tokens")
							}
						}
					})
				}
			}
		})
	}
}
