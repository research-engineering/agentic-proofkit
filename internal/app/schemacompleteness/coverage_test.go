package schemacompleteness

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// SCHEMA-01 execution cross-check of the route reach sets. The CLI is built
// with coverage instrumentation and every argv observation of
// schema-completeness-native-observations.json is replayed. Every module
// function that the replays of a route execute must be in the reach set that
// the owner and "absent" checks of reachability_test.go compute for that
// route, except the functions a --version invocation executes (package
// initialization and argument dispatch, which the route slice does not start
// from). This tests the reach sets against execution;
// it does not prove that an owner runs for every input, and it does not make
// owner lists exhaustive over executed refusal sites.

const schemaCompletenessObservationsPath = "internal/app/testdata/schema-completeness-native-observations.json"

type schemaCompletenessObservation struct {
	Argv             []string          `json:"argv"`
	Corpus           string            `json:"corpus"`
	Direction        string            `json:"direction"`
	Embed            map[string]string `json:"embed"`
	InputObservation *int              `json:"inputObservation"`
	Pointer          string            `json:"pointer"`
	RefusedInput     json.RawMessage   `json:"refusedInput"`
	RepoRootFiles    map[string]string `json:"repoRootFiles"`
	Route            string            `json:"route"`
	Value            json.RawMessage   `json:"value"`
}

func readSchemaCompletenessObservations(t *testing.T, root string) []schemaCompletenessObservation {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(schemaCompletenessObservationsPath)))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Observations []schemaCompletenessObservation `json:"observations"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document.Observations
}

func decodeSchemaJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	err := decoder.Decode(&value)
	return value, err
}

// schemaObservationValue returns the stdin bytes of an observation: its
// value with its embedded test-owned snapshot files, or the corpus value its
// pointer names.
func schemaObservationValue(root string, row schemaCompletenessObservation) ([]byte, error) {
	if row.Value != nil && len(row.Embed) == 0 {
		return row.Value, nil
	}
	if row.Value != nil {
		value, err := decodeSchemaJSON(row.Value)
		if err != nil {
			return nil, err
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("embedding observation value is not an object")
		}
		for pointer, file := range row.Embed {
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
			if err != nil {
				return nil, err
			}
			if object[strings.TrimPrefix(pointer, "/")], err = decodeSchemaJSON(data); err != nil {
				return nil, err
			}
		}
		return json.Marshal(object)
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(row.Corpus)))
	if err != nil {
		return nil, err
	}
	value, err := decodeSchemaJSON(data)
	if err != nil {
		return nil, err
	}
	for _, token := range strings.Split(strings.TrimPrefix(row.Pointer, "/"), "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch node := value.(type) {
		case map[string]any:
			value = node[token]
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(node) {
				return nil, fmt.Errorf("corpus pointer %s does not resolve", row.Pointer)
			}
			value = node[index]
		default:
			return nil, fmt.Errorf("corpus pointer %s does not resolve", row.Pointer)
		}
	}
	return json.Marshal(value)
}

// schemaCoverageRun runs the instrumented CLI once with its counters
// written to directory.
func schemaCoverageRun(t *testing.T, binary string, directory string, argv []string, stdin []byte) []byte {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), binary, argv...)
	command.Dir = filepath.Dir(binary)
	command.Env = append(os.Environ(), "GOCOVERDIR="+directory)
	command.Stdin = bytes.NewReader(stdin)
	var stdout bytes.Buffer
	command.Stdout = &stdout
	if err := command.Run(); err != nil {
		if _, exited := err.(*exec.ExitError); !exited {
			t.Fatalf("%s: %v", strings.Join(argv, " "), err)
		}
	}
	return stdout.Bytes()
}

var schemaCoverageLine = regexp.MustCompile(`^(\S+\.go):\d+:\s+(\S+)\s+([0-9.]+)%$`)

// schemaCoveredFunctions returns the module functions with at least one
// executed statement in a coverage directory.
func schemaCoveredFunctions(t *testing.T, root string, directory string) map[schemaSymbol]struct{} {
	t.Helper()
	command := exec.CommandContext(t.Context(), "go", "tool", "covdata", "func", "-i", directory)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		t.Fatalf("go tool covdata func -i %s: %v", directory, err)
	}
	covered := map[schemaSymbol]struct{}{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		match := schemaCoverageLine.FindStringSubmatch(strings.TrimSpace(scanner.Text()))
		if match == nil || match[3] == "0.0" {
			continue
		}
		name := strings.TrimPrefix(match[2], "*")
		if receiver, method, ok := strings.Cut(name, "."); ok {
			if bracket := strings.IndexByte(receiver, '['); bracket >= 0 {
				receiver = receiver[:bracket]
			}
			name = receiver + "." + method
		}
		covered[schemaSymbol{PackagePath: path.Dir(match[1]), Name: name}] = struct{}{}
	}
	return covered
}

func TestSchemaCompletenessReplayedExecutionStaysWithinRouteReach(t *testing.T) {
	program := loadSchemaCompletenessProgram(t)
	root := schemaRepoRoot(t)
	directory := t.TempDir()
	binary := filepath.Join(directory, "agentic-proofkit")
	build := exec.CommandContext(t.Context(), "go", "build", "-mod=readonly", "-cover", "-coverpkg="+program.modulePath+"/...", "-o", binary, "./cmd/agentic-proofkit")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build instrumented CLI: %v\n%s", err, output)
	}
	schemaCoverageRun(t, binary, filepath.Join(directory, "baseline"), []string{"--version"}, nil)
	baseline := schemaCoveredFunctions(t, root, filepath.Join(directory, "baseline"))

	observations := readSchemaCompletenessObservations(t, root)
	routeDirectories := map[string]string{}
	replays := 0
	for index, row := range observations {
		if row.Argv == nil {
			continue
		}
		var stdin []byte
		var err error
		switch {
		case row.Direction == "input":
			stdin, err = schemaObservationValue(root, row)
		case row.InputObservation != nil:
			stdin, err = schemaObservationValue(root, observations[*row.InputObservation])
		default:
			stdin = row.RefusedInput
		}
		if err != nil {
			t.Fatalf("observation %d: %v", index, err)
		}
		argv := append([]string(nil), row.Argv...)
		if len(row.RepoRootFiles) > 0 {
			repository := filepath.Join(directory, fmt.Sprintf("repository-%d", index))
			if err := os.MkdirAll(repository, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, text := range row.RepoRootFiles {
				if err := os.WriteFile(filepath.Join(repository, name), []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// {repoRoot} names the directory and {repoRoot}/<name> a file in it.
			for position, token := range argv {
				if token == "{repoRoot}" || strings.HasPrefix(token, "{repoRoot}/") {
					argv[position] = repository + strings.TrimPrefix(token, "{repoRoot}")
				}
			}
		}
		if _, ok := routeDirectories[row.Route]; !ok {
			routeDirectories[row.Route] = filepath.Join(directory, fmt.Sprintf("route-%03d", len(routeDirectories)))
		}
		if stdout := schemaCoverageRun(t, binary, routeDirectories[row.Route], argv, stdin); !json.Valid(stdout) {
			t.Fatalf("observation %d %s emitted no JSON", index, strings.Join(row.Argv, " "))
		}
		replays++
	}

	executedByRoute := map[string]map[schemaSymbol]struct{}{}
	executed := 0
	for _, route := range schemaSortedKeys(routeDirectories) {
		if _, ok := program.routes[route]; !ok {
			t.Fatalf("observation route %s has no reach set", route)
		}
		executedByRoute[route] = map[schemaSymbol]struct{}{}
		for symbol := range schemaCoveredFunctions(t, root, routeDirectories[route]) {
			if _, initialization := baseline[symbol]; !initialization {
				executedByRoute[route][symbol] = struct{}{}
				executed++
			}
		}
	}
	if violations := schemaExecutionReachErrors(executedByRoute, program.routes); len(violations) > 0 {
		t.Fatalf("replayed observations executed functions outside their route reach set:\n%s", strings.Join(violations, "\n"))
	}
	if replays == 0 || executed == 0 {
		t.Fatal("no observation replay executed a route function")
	}
	// The comparison has power: the replays of requirement-spec-tree are
	// refused against the reach set of secret-scan.
	swapped := map[string]map[schemaSymbol]struct{}{"requirement-spec-tree": program.routes["secret-scan"]}
	if violations := schemaExecutionReachErrors(map[string]map[schemaSymbol]struct{}{"requirement-spec-tree": executedByRoute["requirement-spec-tree"]}, swapped); len(violations) == 0 {
		t.Fatal("requirement-spec-tree execution fits the secret-scan reach set")
	}
	t.Logf("%d replays over %d routes executed %d (route, function) pairs beyond %d initialization functions; all are in the route reach sets", replays, len(routeDirectories), executed, len(baseline))
}

// schemaExecutionReachErrors returns every executed (route, function) pair
// outside the route's reach set.
func schemaExecutionReachErrors(executedByRoute map[string]map[schemaSymbol]struct{}, reachByRoute map[string]map[schemaSymbol]struct{}) []string {
	violations := []string{}
	for route, executed := range executedByRoute {
		for symbol := range executed {
			if _, reachable := reachByRoute[route][symbol]; !reachable {
				violations = append(violations, route+": "+symbol.String())
			}
		}
	}
	sort.Strings(violations)
	return violations
}
