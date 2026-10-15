package workspaceplanning

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

type workspaceEnvelopeCase struct {
	output map[string]any
	shape  jsonshape.Shape
	schema map[string]any
}

func workspaceEnvelopeCases(t *testing.T) map[string]workspaceEnvelopeCase {
	t.Helper()
	cases := map[string]workspaceEnvelopeCase{}
	for _, scenario := range []string{"selected", "empty", "full", "wide"} {
		input := validChangedPackagePlanInput()
		switch scenario {
		case "empty":
			input["changedPaths"] = []any{}
		case "full":
			input["escalationRules"] = []any{map[string]any{"pattern": "modules/**", "reason": "workspace.global"}}
		case "wide":
			packages := []any{}
			paths := []any{}
			for index := range 25 {
				packages = append(packages, map[string]any{"dirName": fmt.Sprintf("module-%02d", index), "name": fmt.Sprintf("module-%02d", index), "workspaceDependencies": []any{}})
				paths = append(paths, fmt.Sprintf("modules/module-%02d/main.go", index))
			}
			input["packages"] = packages
			input["changedPaths"] = paths
		}
		plan, err := BuildChangedPackagePlan(input)
		if err != nil {
			t.Fatal(err)
		}
		cases["changed/"+scenario] = workspaceEnvelopeCase{BuildChangedPackagePlanEnvelope(plan), ChangedPlanEnvelopeShape(), ChangedPlanEnvelopeStructure()}
	}
	for _, total := range []string{"1", "9", "64", "1024"} {
		for _, failed := range []bool{false, true} {
			if total == "1024" && !failed {
				continue // Populating every shard would exceed the native expansion budget.
			}
			input := validShardPartitionInput()
			input["shardTotal"] = json.Number(total)
			if failed {
				input = emptyShardInput(total)
			} else {
				count, err := strconv.Atoi(total)
				if err != nil {
					t.Fatal(err)
				}
				nodes := make([]any, count)
				for index := range nodes {
					nodes[index] = shardNode(fmt.Sprintf("module-%04d", index))
				}
				input["packages"], input["roots"] = nodes, nodes
			}
			partition, code, err := BuildShardPartition(input)
			if err != nil || (code != 0) != failed {
				t.Fatalf("shards=%s failed=%t: exit=%d error=%v", total, failed, code, err)
			}
			cases[fmt.Sprintf("shard/%s/failed=%t", total, failed)] = workspaceEnvelopeCase{BuildShardPartitionEnvelope(partition), ShardEnvelopeShape(), ShardEnvelopeStructure()}
		}
	}
	return cases
}

func TestWorkspaceEnvelopeStructuresConserveWholeProducerOutputs(t *testing.T) {
	for name, candidate := range workspaceEnvelopeCases(t) {
		t.Run(name, func(t *testing.T) {
			before, err := json.Marshal(candidate.output)
			if err != nil {
				t.Fatal(err)
			}
			if err := candidate.shape.CheckGenerated(candidate.output, "envelope"); err != nil {
				t.Fatal(err)
			}
			if err := schemacheck.Validate(candidate.schema, candidate.output); err != nil {
				t.Fatal(err)
			}
			wire, err := schemacheck.Normalize(candidate.output)
			if err != nil {
				t.Fatal(err)
			}
			admitted, err := candidate.shape.Admit(wire, "envelope")
			if err != nil || !reflect.DeepEqual(admitted, wire) {
				t.Fatalf("wire shape changed: %v", err)
			}
			after, err := json.Marshal(candidate.output)
			if err != nil || string(before) != string(after) {
				t.Fatal("structural description mutated the producer output")
			}
			if candidate.output["costContract"].(map[string]any)["maxTokenBudget"] != 2500 {
				t.Fatal("native workspace token budget changed")
			}
		})
	}
}

func TestWorkspaceEnvelopeStructuresRejectIndependentNestedCorruption(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"reproduced-action-array": func(r map[string]any) { r["actionPlan"] = []any{0} },
		"action-element":          func(r map[string]any) { r["actionPlan"].([]any)[0] = 0 },
		"action-field":            func(r map[string]any) { delete(r["actionPlan"].([]any)[0].(map[string]any), "instruction") },
		"empty-bounds":            func(r map[string]any) { r["bounds"] = map[string]any{} },
		"bounds-field":            func(r map[string]any) { delete(r["bounds"].(map[string]any), "maxActionItems") },
		"negative-bound":          func(r map[string]any) { r["bounds"].(map[string]any)["maxActionItems"] = -1 },
		"zero-budget":             func(r map[string]any) { r["bounds"].(map[string]any)["maxTokenBudget"] = 0 },
		"negative-budget":         func(r map[string]any) { r["bounds"].(map[string]any)["maxTokenBudget"] = -1 },
		"large-budget":            func(r map[string]any) { r["bounds"].(map[string]any)["maxTokenBudget"] = 1 << 20 },
		"primitive-source":        func(r map[string]any) { r["sourceReport"] = 0 },
		"source-field":            func(r map[string]any) { delete(r["sourceReport"].(map[string]any), "state") },
		"primitive-cost":          func(r map[string]any) { r["costContract"] = 0 },
		"cost-field":              func(r map[string]any) { delete(r["costContract"].(map[string]any), "graphQueryCount") },
		"cost-budget":             func(r map[string]any) { r["costContract"].(map[string]any)["maxTokenBudget"] = nil },
		"context-field":           func(r map[string]any) { delete(r["contextRefs"].([]any)[0].(map[string]any), "refId") },
		"omission-field":          func(r map[string]any) { delete(r["omitted"].([]any)[0].(map[string]any), "evidenceRefs") },
		"question-field":          func(r map[string]any) { delete(r["routeQuestions"].([]any)[0].(map[string]any), "question") },
	}
	cases := workspaceEnvelopeCases(t)
	for _, name := range []string{"changed/selected", "shard/1/failed=false"} {
		candidate := cases[name]
		for mutation, mutate := range mutations {
			t.Run(name+"/"+mutation, func(t *testing.T) {
				wire, err := schemacheck.Normalize(candidate.output)
				if err != nil {
					t.Fatal(err)
				}
				record := wire.(map[string]any)
				mutate(record)
				if err := candidate.shape.CheckGenerated(record, "envelope"); err == nil {
					t.Fatal("native structural declaration accepted corruption")
				}
				if err := schemacheck.Validate(candidate.schema, record); err == nil {
					t.Fatal("published structural schema accepted corruption")
				}
			})
		}
	}
}
