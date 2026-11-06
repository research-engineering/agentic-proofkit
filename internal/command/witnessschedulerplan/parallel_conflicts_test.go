package witnessschedulerplan

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestBuildReportsOneCauseForContendedGroup(t *testing.T) {
	input := validSchedulerPlanInput()
	commandTemplate := command(input)
	policyTemplate := schedulerPolicy(input)
	const commandCount = 128
	commands := make([]any, 0, commandCount)
	policies := make([]any, 0, commandCount)
	for i := range commandCount {
		id := fmt.Sprintf("proofkit.command-%03d", i)
		output := fmt.Sprintf("artifacts/proofkit/command-%03d.json", i)
		command := cloneMap(commandTemplate)
		command["id"] = id
		command["expectedArtifacts"] = []any{map[string]any{"kind": "report", "path": output, "required": true}}
		commands = append(commands, command)
		policy := cloneMap(policyTemplate)
		policy["commandId"] = id
		policy["exclusiveLocks"] = []any{"lock.proofkit.shared"}
		policy["outputSelectors"] = []any{output}
		policy["resourceWrites"] = []any{"resource." + id}
		policies = append(policies, policy)
	}
	input["commands"], input["policies"] = commands, policies

	record, exitCode, err := Build(input)
	if err != nil || exitCode != 1 || record.State != "failed" || record.SchemaVersion != 3 {
		t.Fatalf("report schema/state/exit/error = %v/%s/%d/%v", record.SchemaVersion, record.State, exitCode, err)
	}
	const conflict = "parallel group local has exclusive lock collision lock.proofkit.shared"
	failures, ok := record.Diagnostics[1].Value.([]any)
	if !ok || !slices.Equal(failures, []any{conflict}) || record.Summary["failureCount"] != 1 {
		t.Fatalf("failures=%v, summary=%v", failures, record.Summary)
	}
	safety := record.RuleResults[1]
	if safety.Status != "failed" || len(safety.Diagnostics) != 1 || safety.Diagnostics[0].Key != "failure.001" || safety.Diagnostics[0].Value != conflict {
		t.Fatalf("safety rule=%#v", safety)
	}
	nodes := record.Diagnostics[2].Value.([]any)
	if len(nodes) != commandCount {
		t.Fatalf("node digests=%d, want %d", len(nodes), commandCount)
	}
}

func TestDistinctParallelConflictCauses(t *testing.T) {
	commands := []string{"a", "b", "c", "missing"}
	policies := map[string]policy{
		"a": {
			ExclusiveLocks: []string{"lock"}, ResourceReads: []string{"r", "self"}, ResourceWrites: []string{"w", "self"},
			InputSelectors: []string{"self/**", "z"}, OutputSelectors: []string{"self", "a/**"},
			SideEffectClass: "destructive",
		},
		"b": {
			ExclusiveLocks: []string{"lock"}, ResourceReads: []string{"w"}, ResourceWrites: []string{"r", "w"},
			OutputSelectors: []string{"a/sub"},
		},
		"c": {
			ExclusiveLocks: []string{"lock"}, ResourceReads: []string{"w"}, ResourceWrites: []string{"r"},
			OutputSelectors: []string{"z"},
		},
	}
	got := parallelGroupFailures([]executionGroup{{ParallelGroup: "local", CommandIDs: commands}}, policies)
	slices.Sort(got)
	want := []string{
		"parallel group local has exclusive lock collision lock",
		"parallel group local has overlapping input and output selectors",
		"parallel group local has overlapping output selectors",
		"parallel group local has read/write resource collision r",
		"parallel group local has write/read resource collision w",
		"parallel group local has write/write resource collision r",
		"parallel group local has write/write resource collision w",
		"parallel group local must not run destructive commands concurrently",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("conflicts=%q, want %q", got, want)
	}
	if got := parallelGroupFailures([]executionGroup{{ParallelGroup: "local", CommandIDs: []string{"a", "missing"}}}, policies); len(got) != 0 {
		t.Fatalf("same-owner operands generated a pair: %q", got)
	}
}

func TestParallelSelectorConflictsMatchesDirectPairRelation(t *testing.T) {
	selectors := []struct{ raw, prefix string }{
		{"", ""}, {"**", ""}, {"a", "a/"}, {"a/**", "a/"},
		{"a/b", "a/b/"}, {"a/b*", "a/b"}, {"a/bb", "a/bb/"},
		{"a/c", "a/c/"}, {"aa", "aa/"}, {"a1/*.json", "a1/"},
	}
	type selected struct{ input, output int }
	commands := []string{"a", "b", "c"}
	choices := []selected{{}, {1, 0}, {0, 1}, {2, 3}, {3, 4}, {4, 5}, {5, 6}, {6, 7}, {7, 2}, {8, 9}, {9, 8}}
	overlaps := func(a, b int) bool {
		if a == 0 || b == 0 {
			return false
		}
		left, right := selectors[a].prefix, selectors[b].prefix
		return strings.HasPrefix(left, right) || strings.HasPrefix(right, left)
	}
	for _, a := range choices {
		for _, b := range choices {
			for _, c := range choices {
				chosen := []selected{a, b, c}
				policies := map[string]policy{}
				wantOutput, wantMixed := false, false
				for i, pair := range chosen {
					var p policy
					if pair.input != 0 {
						p.InputSelectors = []string{selectors[pair.input].raw}
					}
					if pair.output != 0 {
						p.OutputSelectors = []string{selectors[pair.output].raw}
					}
					policies[commands[i]] = p
					for j := 0; j < i; j++ {
						earlier := chosen[j]
						wantOutput = wantOutput || overlaps(earlier.output, pair.output)
						wantMixed = wantMixed || overlaps(earlier.output, pair.input) || overlaps(earlier.input, pair.output)
					}
				}
				gotOutput, gotMixed := parallelSelectorConflicts(commands, policies)
				if gotOutput != wantOutput || gotMixed != wantMixed {
					t.Fatalf("selectors=%v, conflicts=%v/%v, want %v/%v", chosen, gotOutput, gotMixed, wantOutput, wantMixed)
				}
			}
		}
	}
}
