package workspaceregistry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func registryWire(t *testing.T, value any) any {
	t.Helper()
	data, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := admission.DecodeJSON(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func enabledPoliciesInput() map[string]any {
	input := validWorkspaceRegistryInput()
	input["root"].(map[string]any)["dependencyRefs"] = []any{map[string]any{"field": "dependencies", "name": "@example/alpha", "version": "workspace:*"}}
	input["dependencyPolicy"] = map[string]any{"internalNamePrefixes": []any{"@example/"}, "workspaceVersion": "workspace:*"}
	input["lockfilePolicy"] = map[string]any{
		"lockfileText":     `{"lockfileVersion": 1, "workspaces": {"": {"name": "example-root"}, "packages/alpha": {}}, "packages": {"@example/alpha": ["@example/alpha@workspace:packages/alpha"]}}`,
		"expectedSnippets": []any{map[string]any{"snippet": `"lockfileVersion": 1`, "failureMessage": "bun.lock version drifted"}},
	}
	return input
}

func failingPoliciesInput() map[string]any {
	input := enabledPoliciesInput()
	input["knownPackageNames"] = []any{"@example/alpha", "@example/beta"}
	root := input["root"].(map[string]any)
	root["dependencyRefs"] = []any{
		map[string]any{"field": "dependencies", "name": "@example/ghost", "version": "workspace:*"},
		map[string]any{"field": "dependencies", "name": "@example/alpha", "version": "1.0.0"},
	}
	root["scripts"] = append(root["scripts"].([]any), map[string]any{"name": "odd", "command": "bun run --filter @example/missing x"})
	policy := input["scriptPolicy"].(map[string]any)
	policy["requiredRootScriptNames"] = []any{"lint"}
	policy["requiredPackageScriptNames"] = []any{"build", "test"}
	policy["exactRootScripts"] = []any{map[string]any{"name": "quality", "command": "different"}}
	input["lockfilePolicy"] = map[string]any{"lockfileText": `"name": "other"`, "expectedSnippets": []any{map[string]any{"snippet": "zzz", "failureMessage": "custom missing"}}}
	return input
}

func TestOutputStructureCoversPassedFailedAndSkippedRules(t *testing.T) {
	minimal := validWorkspaceRegistryInput()
	delete(minimal, "dependencyPolicy")
	delete(minimal, "lockfilePolicy")
	delete(minimal, "nonClaims")
	delete(minimal["scriptPolicy"].(map[string]any), "admittedRootScriptNames")
	statuses := map[string]map[string]bool{}
	for _, row := range []struct {
		name  string
		input map[string]any
		state string
	}{
		{"skipped policies", validWorkspaceRegistryInput(), "passed"}, {"enabled policies", enabledPoliciesInput(), "passed"},
		// An absent admittedRootScriptNames leaves root scripts unrestricted (C-02).
		{"failed policies", failingPoliciesInput(), "failed"}, {"absent optional policy", minimal, "passed"},
	} {
		t.Run(row.name, func(t *testing.T) {
			record, code, err := Build(registryWire(t, row.input))
			if err != nil || record.State != row.state || (code == 0) != (row.state == "passed") {
				t.Fatalf("native state changed: code=%d err=%v state=%s", code, err, record.State)
			}
			value := record.JSONValue()
			if err := OutputShape().CheckGenerated(value, "workspace registry"); err != nil {
				t.Fatal(err)
			}
			wire := registryWire(t, value).(map[string]any)
			if _, err := OutputShape().Admit(wire, "workspace registry wire"); err != nil {
				t.Fatal(err)
			}
			if wire["reportId"] != reportKind || !reflect.DeepEqual(wire["nonClaims"].([]any)[:len(registryNonClaims)], stringsToAny(registryNonClaims)) {
				t.Fatal("published reportId/nonClaims refinement no longer matches native output")
			}
			for _, raw := range wire["ruleResults"].([]any) {
				rule := raw.(map[string]any)
				if statuses[rule["ruleId"].(string)] == nil {
					statuses[rule["ruleId"].(string)] = map[string]bool{}
				}
				statuses[rule["ruleId"].(string)][rule["status"].(string)] = true
			}
			for _, key := range slices.Sorted(maps.Keys(wire)) {
				missing := maps.Clone(wire)
				delete(missing, key)
				if _, err := OutputShape().Admit(missing, "workspace registry"); err == nil {
					t.Fatalf("missing %s admitted", key)
				}
			}
			swapped := maps.Clone(wire)
			swapped["state"] = map[string]string{"passed": "failed", "failed": "passed"}[row.state]
			if _, err := OutputShape().Admit(swapped, "workspace registry"); err == nil {
				t.Fatal("report state became independent of failures")
			}
		})
	}
	for _, rule := range ruleInventory() {
		want := []string{"failed", "passed"}
		if rule.enabled != "" {
			want = append(want, "skipped")
		}
		if got := slices.Sorted(maps.Keys(statuses[rule.id])); !slices.Equal(got, want) {
			t.Fatalf("%s reachable statuses=%v want %v", rule.id, got, want)
		}
	}
}

func TestOutputStructureBindsNativeRuleInventory(t *testing.T) {
	record, _, err := Build(registryWire(t, failingPoliciesInput()))
	if err != nil {
		t.Fatal(err)
	}
	inventory := map[string]ruleCounters{}
	for _, rule := range ruleInventory() {
		inventory[rule.id] = rule
	}
	if len(record.RuleResults) != len(inventory) {
		t.Fatal("native rule inventory changed")
	}
	for _, rule := range record.RuleResults {
		spec, ok := inventory[rule.RuleID]
		if !ok {
			t.Fatalf("undescribed native rule %s", rule.RuleID)
		}
		keys := []string{}
		for _, diagnostic := range rule.Diagnostics {
			if !strings.HasPrefix(diagnostic.Key, failureDiagnosticPrefix) {
				keys = append(keys, diagnostic.Key)
			}
		}
		want := slices.Sorted(maps.Keys(spec.counters))
		if spec.enabled != "" {
			want = slices.Sorted(slices.Values(append(want, spec.enabled)))
		}
		if !slices.Equal(slices.Sorted(slices.Values(keys)), want) {
			t.Fatalf("%s counters=%v want %v", rule.RuleID, keys, want)
		}
	}
	ordinal := regexp.MustCompile(`\A` + failureOrdinalPattern + `\z`)
	for _, index := range []int{1, 9, 10, 99, 100, 999, 1000, 12345} {
		if !ordinal.MatchString(fmt.Sprintf("%03d", index)) {
			t.Fatalf("native ordinal %d is outside the described grammar", index)
		}
	}
	for _, spelling := range []string{"000", "1", "01", "0001", "-01", "1a0"} {
		if ordinal.MatchString(spelling) {
			t.Fatalf("non-native ordinal %q admitted", spelling)
		}
	}
	structure := OutputStructure()
	for _, raw := range structure["oneOf"].([]any) {
		properties := raw.(map[string]any)["properties"].(map[string]any)
		if properties["reportId"].(map[string]any)["const"] != reportKind || len(properties["nonClaims"].(map[string]any)["prefixItems"].([]any)) != len(registryNonClaims) {
			t.Fatal("output refinement lost a native literal")
		}
	}
	if !reflect.DeepEqual(InputStructure()["required"], []any{"knownPackageNames", "packages", "root", "schemaVersion", "scriptPolicy"}) {
		t.Fatal("native optional root members drifted")
	}
}

func TestInputStructureAgreesWithNativeAdmission(t *testing.T) {
	type mutation struct {
		name   string
		mutate func(map[string]any)
		// nativeOnly marks semantic predicates the structure names but cannot express.
		accepted, nativeOnly bool
	}
	object := func(input map[string]any, path ...any) map[string]any {
		var current any = input
		for _, segment := range path {
			switch key := segment.(type) {
			case string:
				current = current.(map[string]any)[key]
			case int:
				current = current.([]any)[key]
			}
		}
		return current.(map[string]any)
	}
	set := func(value any, key string, path ...any) func(map[string]any) {
		return func(input map[string]any) { object(input, path...)[key] = value }
	}
	remove := func(key string, path ...any) func(map[string]any) {
		return func(input map[string]any) { delete(object(input, path...), key) }
	}
	cases := []mutation{
		{name: "valid", mutate: func(map[string]any) {}, accepted: true},
		{name: "enabled policies", mutate: func(input map[string]any) { maps.Copy(input, enabledPoliciesInput()) }, accepted: true},
		{name: "failing policies", mutate: func(input map[string]any) { maps.Copy(input, failingPoliciesInput()) }, accepted: true},
		{name: "foreign root", mutate: set(true, "foreign")},
		{name: "version two", mutate: set(json.Number("2"), "schemaVersion")},
		{name: "absent policies", mutate: func(input map[string]any) { delete(input, "dependencyPolicy"); delete(input, "lockfilePolicy") }, accepted: true},
		{name: "dependency policy array", mutate: set([]any{}, "dependencyPolicy")},
		{name: "lockfile policy false", mutate: set(false, "lockfilePolicy")},
		{name: "nonClaims absent", mutate: remove("nonClaims"), accepted: true},
		{name: "nonClaims null", mutate: set(nil, "nonClaims")},
		{name: "nonClaims blank", mutate: set([]any{"\u3000"}, "nonClaims")},
		{name: "known empty", mutate: set([]any{}, "knownPackageNames")},
		{name: "known duplicate", mutate: set([]any{"@example/alpha", " @example/alpha"}, "knownPackageNames"), nativeOnly: true},
		{name: "known secret", mutate: set([]any{"token=ghp_secretvalue"}, "knownPackageNames"), nativeOnly: true},
		{name: "root name absent", mutate: remove("name", "root"), accepted: true},
		{name: "root name null", mutate: set(nil, "name", "root")},
		{name: "root refs absent", mutate: remove("dependencyRefs", "root"), accepted: true},
		{name: "root refs null", mutate: set(nil, "dependencyRefs", "root"), accepted: true},
		{name: "root refs object", mutate: set(map[string]any{}, "dependencyRefs", "root")},
		{name: "root scripts absent", mutate: remove("scripts", "root")},
		{name: "root scripts null", mutate: set(nil, "scripts", "root")},
		{name: "root foreign", mutate: set(true, "foreign", "root")},
		{name: "script command multiline", mutate: set("bun run\ntest", "command", "root", "scripts", 0)},
		{name: "script command padded newline", mutate: set("\r\nbun run test\n", "command", "root", "scripts", 0), accepted: true},
		{name: "script command NUL", mutate: set("bun\x00run", "command", "root", "scripts", 0)},
		{name: "script command tab", mutate: set("bun\trun test", "command", "root", "scripts", 0), accepted: true},
		{name: "script name absent", mutate: remove("name", "root", "scripts", 0)},
		{name: "script foreign", mutate: set(true, "foreign", "root", "scripts", 0)},
		{name: "duplicate script names", mutate: func(input map[string]any) {
			scripts := object(input, "root")["scripts"].([]any)
			object(input, "root")["scripts"] = append(scripts, map[string]any{"name": " quality", "command": "bun run other"})
		}, nativeOnly: true},
		{name: "packages empty", mutate: set([]any{}, "packages"), accepted: true},
		{name: "package dirName slash", mutate: set("alpha/beta", "dirName", "packages", 0)},
		{name: "package dirName backslash", mutate: set(`alpha\beta`, "dirName", "packages", 0)},
		{name: "package dirName dot", mutate: set(" . ", "dirName", "packages", 0)},
		{name: "package dirName dots", mutate: set("..", "dirName", "packages", 0)},
		{name: "package dirName triple dot", mutate: set("...", "dirName", "packages", 0), accepted: true},
		{name: "package dirName dotted", mutate: set(".a", "dirName", "packages", 0), accepted: true},
		{name: "package dirName trailing dot", mutate: set("a.", "dirName", "packages", 0), accepted: true},
		{name: "package dirName padded spaced", mutate: set("\talpha beta ", "dirName", "packages", 0), accepted: true},
		{name: "package dirName NUL", mutate: set("al\x00pha", "dirName", "packages", 0)},
		{name: "package dirName blank", mutate: set("  ", "dirName", "packages", 0)},
		{name: "package refs null", mutate: set(nil, "dependencyRefs", "packages", 0), accepted: true},
		{name: "package name absent", mutate: remove("name", "packages", 0)},
		{name: "package foreign", mutate: set(true, "foreign", "packages", 0)},
		{name: "duplicate packages", mutate: func(input map[string]any) {
			input["packages"] = append(input["packages"].([]any), maps.Clone(object(input, "packages", 0)))
		}, nativeOnly: true},
		{name: "dependency ref missing version", mutate: func(input map[string]any) {
			object(input, "root")["dependencyRefs"] = []any{map[string]any{"field": "dependencies", "name": "@example/alpha"}}
		}},
		{name: "dependency ref foreign", mutate: func(input map[string]any) {
			object(input, "root")["dependencyRefs"] = []any{map[string]any{"field": "dependencies", "name": "@example/alpha", "version": "1", "foreign": true}}
		}},
		{name: "policy optional lists absent", mutate: func(input map[string]any) {
			for _, key := range []string{"admittedRootScriptNames", "exactRootScripts", "requiredPackageScriptNames", "requiredRootScriptNames"} {
				delete(object(input, "scriptPolicy"), key)
			}
		}, accepted: true},
		{name: "policy optional lists null", mutate: func(input map[string]any) {
			for _, key := range []string{"admittedRootScriptNames", "exactRootScripts", "requiredPackageScriptNames", "requiredRootScriptNames"} {
				object(input, "scriptPolicy")[key] = nil
			}
		}, accepted: true},
		{name: "policy target options empty", mutate: set([]any{}, "targetOptionNames", "scriptPolicy")},
		{name: "policy self options absent", mutate: remove("selfTargetOptionNames", "scriptPolicy")},
		{name: "policy prefixes null", mutate: set(nil, "targetNamePrefixes", "scriptPolicy")},
		{name: "policy foreign", mutate: set(true, "foreign", "scriptPolicy")},
		{name: "exact script command absent", mutate: set([]any{map[string]any{"name": "quality"}}, "exactRootScripts", "scriptPolicy"), accepted: true},
		{name: "exact script command null", mutate: set([]any{map[string]any{"name": "quality", "command": nil}}, "exactRootScripts", "scriptPolicy")},
		{name: "exact script foreign", mutate: set([]any{map[string]any{"name": "quality", "foreign": true}}, "exactRootScripts", "scriptPolicy")},
		{name: "dependency label absent", mutate: func(input map[string]any) {
			input["dependencyPolicy"] = map[string]any{"internalNamePrefixes": []any{"@example/"}, "workspaceVersion": "workspace:*"}
		}, accepted: true},
		{name: "dependency label null", mutate: func(input map[string]any) {
			input["dependencyPolicy"] = map[string]any{"internalDependencyLabel": nil, "internalNamePrefixes": []any{"@example/"}, "workspaceVersion": "workspace:*"}
		}},
		{name: "dependency prefixes empty", mutate: func(input map[string]any) {
			input["dependencyPolicy"] = map[string]any{"internalNamePrefixes": []any{}, "workspaceVersion": "workspace:*"}
		}},
		{name: "dependency policy foreign", mutate: func(input map[string]any) {
			input["dependencyPolicy"] = map[string]any{"internalNamePrefixes": []any{"@example/"}, "workspaceVersion": "workspace:*", "foreign": true}
		}},
		{name: "lockfile snippets absent", mutate: set(map[string]any{"lockfileText": "lockfile"}, "lockfilePolicy"), accepted: true},
		{name: "lockfile snippets null", mutate: set(map[string]any{"lockfileText": "lockfile", "expectedSnippets": nil}, "lockfilePolicy"), accepted: true},
		{name: "lockfile text absent", mutate: set(map[string]any{"expectedSnippets": []any{}}, "lockfilePolicy")},
		{name: "lockfile snippet message absent", mutate: set(map[string]any{"lockfileText": "lockfile", "expectedSnippets": []any{map[string]any{"snippet": "x"}}}, "lockfilePolicy")},
		{name: "lockfile snippet secret", mutate: set(map[string]any{"lockfileText": "lockfile", "expectedSnippets": []any{map[string]any{"snippet": "x", "failureMessage": "token=ghp_secretvalue"}}}, "lockfilePolicy"), nativeOnly: true},
		{name: "lockfile foreign", mutate: set(map[string]any{"lockfileText": "lockfile", "foreign": true}, "lockfilePolicy")},
	}
	for _, key := range []string{"knownPackageNames", "packages", "root", "schemaVersion", "scriptPolicy"} {
		cases = append(cases, mutation{name: "missing " + key, mutate: remove(key)})
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validWorkspaceRegistryInput()
			item.mutate(input)
			wire := registryWire(t, input)
			_, nativeErr := admitInput(wire)
			_, structuralErr := InputShape().Admit(wire, "workspace registry structure")
			if (nativeErr == nil) != item.accepted {
				t.Fatalf("native admission=%v want accepted=%v", nativeErr, item.accepted)
			}
			if item.nativeOnly {
				if structuralErr != nil {
					t.Fatalf("structure refused a native-only predicate: %v", structuralErr)
				}
				return
			}
			if (structuralErr == nil) != item.accepted {
				t.Fatalf("structure=%v native=%v", structuralErr, nativeErr)
			}
		})
	}
}
