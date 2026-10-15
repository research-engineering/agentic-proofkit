package workflowsmoke

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// TestTrajectorySchedulerDeclaresEveryFixtureInput holds the fixture scheduler
// to the witness-scheduler-plan input guide: each policy's inputSelectors name
// every repository path its native command reads, at each planned scheduler.
func TestTrajectorySchedulerDeclaresEveryFixtureInput(t *testing.T) {
	initial := trajectoryNativeFiles()
	migratedFiles, removed := trajectoryMigratedFiles()
	migrated := maps.Clone(initial)
	maps.Copy(migrated, migratedFiles)
	for _, path := range removed {
		delete(migrated, path)
	}
	migratedSpec := trajectoryInitialSpec()
	migratedSpec.Migrated = true
	for _, state := range []struct {
		label string
		spec  trajectorySpec
		files map[string]string
	}{
		{"initial", trajectoryInitialSpec(), initial},
		{"migrated", migratedSpec, migrated},
	} {
		declared := map[string][]any{}
		for _, raw := range trajectoryPolicies(state.spec) {
			policy := raw.(map[string]any)
			declared[policy["commandId"].(string)] = policy["inputSelectors"].([]any)
		}
		for _, edge := range trajectoryEdges(state.spec) {
			reads := trajectoryFixtureReads(t, edge, state.files)
			if !slices.Contains(reads, edge.WitnessPath) {
				t.Fatalf("%s %s reads %v without its witness %s", state.label, edge.CommandID, reads, edge.WitnessPath)
			}
			for _, path := range reads {
				if !trajectorySelectorsCover(declared[edge.CommandID], path) {
					t.Errorf("%s %s inputSelectors %v omit read path %s", state.label, edge.CommandID, declared[edge.CommandID], path)
				}
			}
		}
	}
}

// trajectoryFixtureReads derives, independently of the declared policy, the
// fixture paths one native command reads: go.mod and every Go file of the
// package that go test compiles, or the Python witness module and every file
// of the fixture packages it imports.
func trajectoryFixtureReads(t *testing.T, edge trajectoryEdge, files map[string]string) []string {
	t.Helper()
	fields := strings.Fields(edge.Command)
	reads := []string{}
	underDirectory := func(directory string, suffix string) {
		for path := range files {
			if strings.HasPrefix(path, directory+"/") && strings.HasSuffix(path, suffix) {
				reads = append(reads, path)
			}
		}
	}
	switch {
	case len(fields) >= 3 && fields[0] == "go" && fields[1] == "test":
		reads = append(reads, "go.mod")
		underDirectory(strings.TrimPrefix(fields[2], "./"), ".go")
	case len(fields) == 4 && fields[0] == "python3" && fields[1] == "-m" && fields[2] == "unittest":
		module := strings.ReplaceAll(fields[3], ".", "/") + ".py"
		reads = append(reads, module)
		for _, line := range strings.Split(files[module], "\n") {
			if imported, ok := strings.CutPrefix(line, "from "); ok {
				underDirectory(strings.ReplaceAll(strings.Fields(imported)[0], ".", "/"), "")
			}
		}
	default:
		t.Fatalf("fixture command %q has no read model", edge.Command)
	}
	for _, path := range reads {
		if _, ok := files[path]; !ok {
			t.Fatalf("%s reads absent fixture path %s", edge.CommandID, path)
		}
	}
	slices.Sort(reads)
	return reads
}

func trajectorySelectorsCover(selectors []any, path string) bool {
	for _, raw := range selectors {
		selector, _ := raw.(string)
		if path == selector || strings.HasPrefix(path, selector+"/") {
			return true
		}
	}
	return false
}
