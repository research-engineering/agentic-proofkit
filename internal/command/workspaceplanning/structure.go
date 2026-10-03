package workspaceplanning

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

var changedInputKeys = []string{"changedPaths", "escalationRules", "includeReverseDependents", "packages", "packagesRoot", "schemaVersion"}
var shardInputKeys = []string{"packages", "roots", "schemaVersion", "shardTotal"}
var pathNodeKeys = []string{"dirName", "name", "workspaceDependencies"}
var dependencyNodeKeys = []string{"name", "workspaceDependencies"}
var escalationRuleKeys = []string{"pattern", "reason"}

// ShardPackageStructure owns the package record consumed by shard planning.
func ShardPackageStructure() jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return jsonshape.RequiredObject(dependencyNodeKeys, map[string]jsonshape.Shape{
		"name": text, "workspaceDependencies": jsonshape.Array(text, 0),
	})
}

// ChangedPlanPackageStructure extends the shard record with its path identity.
func ChangedPlanPackageStructure() jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return jsonshape.RequiredObject(pathNodeKeys, map[string]jsonshape.Shape{
		"dirName": jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes),
		"name":    text, "workspaceDependencies": jsonshape.Array(text, 0),
	})
}

func ChangedPlanInputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	rule := jsonshape.RequiredObject(escalationRuleKeys, map[string]jsonshape.Shape{"pattern": text, "reason": id})
	schema := jsonshape.ObjectFromKeys(changedInputKeys, map[string]jsonshape.Shape{
		"changedPaths": jsonshape.Array(text, 0), "escalationRules": jsonshape.Array(rule, 0),
		"includeReverseDependents": jsonshape.Boolean(), "packages": jsonshape.Array(ChangedPlanPackageStructure(), 0),
		"packagesRoot": text, "schemaVersion": jsonshape.IntegerLiteral(1),
	}, "includeReverseDependents", "packagesRoot").JSONSchema()
	fields := schema["properties"].(map[string]any)
	fields["includeReverseDependents"].(map[string]any)["default"] = true
	fields["packagesRoot"].(map[string]any)["default"] = "packages"
	schema["description"] = "Only includeReverseDependents and packagesRoot are optional; absence uses true and packages respectively, while null is rejected. Native admission owns canonical integer spelling, RuleID privacy, safe repository-relative paths and path-pattern grammar. Package names and dependency text trim; paths and dependencies sort without deduplication. Package names and dirName identities must be unique after admission. Package order is preserved in selection. Missing dependency targets and cycles are not rejected by this selection-only command. JSON Schema does not implement normalization, privacy, path semantics or identity-key uniqueness."
	return schema
}

func ChangedPlanOutputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	texts := jsonshape.Array(text, 0)
	nodes := jsonshape.Array(ChangedPlanPackageStructure(), 0)
	schema := jsonshape.Object(
		jsonshape.Required("changedPaths", texts), jsonshape.Required("directRootPackageNames", texts),
		jsonshape.Required("directRoots", nodes), jsonshape.Required("escalationReasons", jsonshape.Array(jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes), 0)),
		jsonshape.Required("fullWorkspace", jsonshape.Boolean()), jsonshape.Required("rootPackageNames", texts),
		jsonshape.Required("roots", nodes), jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
	).JSONSchema()
	fields := schema["properties"].(map[string]any)
	for _, key := range []string{"directRootPackageNames", "directRoots", "escalationReasons", "rootPackageNames", "roots"} {
		fields[key].(map[string]any)["uniqueItems"] = true
	}
	schema["description"] = "Direct roots follow changed paths under packagesRoot. Matching caller escalation selects every package; otherwise the optional reverse-dependent closure extends direct roots. Selected records and names retain input package order. Escalation reasons are sorted unique; changedPaths and workspaceDependencies may contain duplicates. Parallel arrays and fullWorkspace are derived relationships, not structural proof of graph freshness, command execution or gate success."
	return schema
}

func ShardInputStructure() map[string]any {
	nodes := jsonshape.Array(ShardPackageStructure(), 0)
	schema := jsonshape.RequiredObject(shardInputKeys, map[string]jsonshape.Shape{
		"packages": nodes, "roots": nodes, "schemaVersion": jsonshape.IntegerLiteral(1),
		"shardTotal": jsonshape.IntegerMinimum(1),
	}).JSONSchema()
	schema["description"] = "All root fields are required; arrays may be empty. Native shardTotal is a canonical positive int64 also representable as host int; JSON Schema alone does not enforce wire token spelling or host integer range. No small operational shard limit is asserted by this structure. Names and dependency text trim; dependency lists sort without deduplication. Root order determines modulo shard ownership. Duplicate identities, missing dependencies and cycles are evaluated by the native planner and may produce failed reports rather than input errors. Structure does not prove graph consistency, privacy or feasible resource cost."
	return schema
}

func ShardOutputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	texts := jsonshape.Array(text, 0)
	index, total := jsonshape.IntegerMinimum(0), jsonshape.IntegerMinimum(1)
	label := jsonshape.StringGrammar(`[1-9][0-9]*-of-[1-9][0-9]*`)
	shard := jsonshape.Object(
		jsonshape.Required("dependencyClosurePackageNames", texts), jsonshape.Required("executionPackageNames", texts),
		jsonshape.Required("rootPackageNames", texts), jsonshape.Required("shardIndex", index),
		jsonshape.Required("shardLabel", label), jsonshape.Required("shardTotal", total),
	)
	matrix := jsonshape.Object(jsonshape.Required("include", jsonshape.Array(jsonshape.Object(
		jsonshape.Required("shard_index", index), jsonshape.Required("shard_label", label), jsonshape.Required("shard_total", total),
	), 1)))
	schema := jsonshape.Object(
		jsonshape.Required("failures", texts), jsonshape.Required("packageShards", matrix),
		jsonshape.Required("rootPackageCount", index), jsonshape.Required("rootPackageNames", texts),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)), jsonshape.Required("shardTotal", total),
		jsonshape.Required("shards", jsonshape.Array(shard, 1)),
	).JSONSchema()
	fields := schema["properties"].(map[string]any)
	for _, key := range []string{"failures", "rootPackageNames"} {
		fields[key].(map[string]any)["uniqueItems"] = true
	}
	schema["description"] = "Both successful and failed partitions have this shape. Exit zero means failures is empty; exit one with a report means evaluation failed. Shard indices are zero-based, labels one-based, and both arrays have shardTotal records. Root names are unique in first-observed order; shard-owned root names may repeat in failed reports. Closures/execution use native dependency order. Count, matrix equality, name linkage and graph semantics are native derived invariants, not JSON Schema equality checks. Reports and optional agent envelopes do not execute gates or grant CI/merge authority."
	return schema
}
