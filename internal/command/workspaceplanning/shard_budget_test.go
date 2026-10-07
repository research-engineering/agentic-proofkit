package workspaceplanning

import (
	"encoding/json"
	"strings"
	"testing"
)

func emptyShardInput(total string) map[string]any {
	return map[string]any{"schemaVersion": json.Number("1"), "packages": []any{}, "roots": []any{}, "shardTotal": json.Number(total)}
}

func shardNode(name string, dependencies ...any) map[string]any {
	if dependencies == nil {
		dependencies = []any{}
	}
	return map[string]any{"name": name, "workspaceDependencies": dependencies}
}

func TestShardCountBudgetPrecedesNestedAdmission(t *testing.T) {
	for _, count := range []string{"1025", "9223372036854775807"} {
		input := emptyShardInput(count)
		input["packages"] = []any{false}
		report, _, err := BuildShardPartition(input)
		if report != nil || err == nil || !strings.Contains(err.Error(), "workspace shard total") {
			t.Fatalf("count budget did not precede nested work: %v", err)
		}
	}
	for _, count := range []string{"1", "1024"} {
		report, code, err := BuildShardPartition(emptyShardInput(count))
		want := 1
		if count == "1024" {
			want = 1024
		}
		if err != nil || code != 1 || len(report["shards"].([]any)) != want {
			t.Fatalf("inclusive count limit or empty failed report changed: %d %v", code, err)
		}
	}
}

func TestShardExpansionCountsRepeatedNodesAndEdges(t *testing.T) {
	input := emptyShardInput("1024")
	nodes := make([]any, 1023)
	for index := range nodes {
		nodes[index] = shardNode("same")
	}
	input["packages"] = nodes
	if _, err := admitShardInput(input); err != nil {
		t.Fatalf("exact work limit rejected: %v", err)
	}
	input["packages"] = append(nodes, shardNode("same"))
	if report, _, err := BuildShardPartition(input); report != nil || err == nil || !strings.Contains(err.Error(), "work-item limit") {
		t.Fatalf("repeated nodes bypassed expansion budget: %v", err)
	}
	dependencies := make([]any, 1022)
	for index := range dependencies {
		dependencies[index] = "same"
	}
	input["packages"] = []any{shardNode("same", dependencies...)}
	if _, err := admitShardInput(input); err != nil {
		t.Fatalf("exact edge limit rejected: %v", err)
	}
	input["packages"] = []any{shardNode("same", append(dependencies, "same")...)}
	if report, _, err := BuildShardPartition(input); report != nil || err == nil || !strings.Contains(err.Error(), "work-item limit") {
		t.Fatalf("duplicate edges bypassed expansion budget: %v", err)
	}
	input["packages"] = []any{shardNode("same", dependencies...)}
	input["roots"] = []any{shardNode("root")}
	if _, err := admitShardInput(input); err == nil || !strings.Contains(err.Error(), "work-item limit") {
		t.Fatalf("dependencies did not reduce the budget for later roots: %v", err)
	}
	input["packages"] = nodes[:1022]
	input["roots"] = []any{shardNode("same")}
	if _, err := admitShardInput(input); err != nil {
		t.Fatalf("root occurrence within limit rejected: %v", err)
	}
	input["roots"] = []any{shardNode("same"), shardNode("same")}
	if _, err := admitShardInput(input); err == nil || !strings.Contains(err.Error(), "work-item limit") {
		t.Fatalf("roots were not charged: %v", err)
	}
}

func TestShardExpansionChargesNormalizedUTF8Bytes(t *testing.T) {
	for _, name := range []string{strings.Repeat("x", 16384), strings.Repeat("\u00e9", 8192)} {
		input := emptyShardInput("1024")
		input["packages"] = []any{shardNode("  " + name + "  ")}
		if _, err := admitShardInput(input); err != nil {
			t.Fatalf("exact normalized byte limit rejected: %v", err)
		}
		input["packages"] = []any{shardNode(name + "x")}
		if report, _, err := BuildShardPartition(input); report != nil || err == nil || !strings.Contains(err.Error(), "text-byte limit") {
			t.Fatalf("byte overflow admitted: %v", err)
		}
	}
	input := emptyShardInput("1024")
	input["packages"] = []any{shardNode("x", strings.Repeat("y", 16383))}
	if _, err := admitShardInput(input); err != nil {
		t.Fatal(err)
	}
	input["roots"] = []any{shardNode("x")}
	if _, err := admitShardInput(input); err == nil || !strings.Contains(err.Error(), "text-byte limit") {
		t.Fatalf("root/dependency text not charged: %v", err)
	}
}
