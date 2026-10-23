package main

import (
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/secretjson"
)

var visualProofNonClaims = []string{
	"A passed record proves only that every listed reference view produced, in two byte-equal captures, its admitted canonical RGBA digest and dimensions in the recorded reference environment before record creation.",
	"Only the first 2400 CSS pixels of each view are compared; content below that height is not covered by a reference.",
	"An unverified record makes no pixel claim; it lists the compared environment fields that differ from the recorded reference environment.",
	"The CPU vendor, model and features are recorded but are not part of the compared environment identity; pixel identity is calibrated only on Apple M1 (implementer 0x61) and Arm Neoverse N2 (implementer 0x41, part 0xd49).",
	"Admitted images are not stored in the repository; they are reproducible from the admitting commit in the recorded environment on a calibrated CPU model while the pinned image and the pinned toolchain and dependency downloads remain available, and an uploaded capture gallery is derived, retention-limited evidence.",
	"This record does not identify who reviewed or admitted a reference.",
	"Playwright WebKit is not branded Safari compatibility proof.",
	"A dirty-tree record is content-bound only to its listed assets; sourceRevision is contextual.",
	"This record does not independently authenticate or sandbox the same-user proof runner, the container image beyond its observed tuple, external toolchain packages, or browser binaries.",
}

var visualCommandArgv = []string{"node_modules/@playwright/test/cli.js", "test", "--config", "playwright.visual.config.mjs"}

// verifyVisualRecord admits a passed or unverified visual record. It binds the
// record to the content-bound inputs, the committed reference inventory and
// environment identity, and recomputes the environment divergence itself; a
// passed record must also carry every engine's exact expected test set.
func verifyVisualRecord(root string, raw any, expectedResolution proofInputResolution, revision, treeState string) error {
	record, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("browser visual proof must be an object")
	}
	if err := admit.KnownKeys(record, []string{"assets", "command", "divergentFields", "engines", "inputDigest", "inputResolution", "nonClaims", "observedEnvironment", "projects", "proofKind", "referenceEnvironment", "schemaVersion", "sourceRevision", "sourceTreeState", "state"}, "browser visual proof"); err != nil {
		return err
	}
	kind := visualProofKind()
	state, _ := record["state"].(string)
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) || record["proofKind"] != kind.RecordKind || !kind.admitsState(state) ||
		record["sourceRevision"] != revision || record["sourceTreeState"] != treeState {
		return fmt.Errorf("browser visual proof identity or source state is invalid")
	}
	if err := exactTextArray(record["nonClaims"], visualProofNonClaims, "browser visual proof nonClaims"); err != nil {
		return err
	}
	if err := verifyContentBoundInputs(root, record, expectedResolution, "browser visual proof"); err != nil {
		return err
	}
	inventory, err := verifyVisualReferences(root)
	if err != nil {
		return err
	}
	reference, ok := record["referenceEnvironment"].(map[string]any)
	if !ok || admit.KnownKeys(reference, []string{"environmentId", "referenceCount", "referencesDigest"}, "browser visual proof referenceEnvironment") != nil ||
		reference["environmentId"] != inventory.EnvironmentID || reference["referencesDigest"] != inventory.ReferencesDigest ||
		!admit.JSONNumberEquals(reference["referenceCount"], int64(inventory.Count)) {
		return fmt.Errorf("browser visual proof is not bound to the committed reference inventory")
	}
	environment, err := loadVisualEnvironment(root)
	if err != nil {
		return err
	}
	observed, ok := record["observedEnvironment"].(map[string]any)
	if !ok || admit.KnownKeys(observed, append([]string{"cpu"}, visualComparedEnvironmentFields...), "browser visual proof observedEnvironment") != nil ||
		len(observed) != len(visualComparedEnvironmentFields)+1 {
		return fmt.Errorf("browser visual proof must record the complete observed environment")
	}
	if err := admitObservedTuple(observed, false); err != nil {
		return err
	}
	if err := admitObservedCPU(observed["cpu"]); err != nil {
		return err
	}
	divergent, err := visualEnvironmentDivergence(environment.Observed, observed)
	if err != nil {
		return err
	}
	if err := exactTextArray(record["divergentFields"], divergent, "browser visual proof divergentFields"); err != nil {
		return err
	}
	if (state == "passed") != (len(divergent) == 0) {
		return fmt.Errorf("browser visual proof state must be passed exactly when the observed environment equals the reference environment")
	}
	if state == "unverified" {
		if record["command"] != nil || !emptyArray(record["engines"]) || !emptyArray(record["projects"]) {
			return fmt.Errorf("unverified browser visual proof must not claim a browser execution")
		}
	} else {
		if err := verifyVisualExecution(record, environment); err != nil {
			return err
		}
	}
	findings, err := secretjson.Scan(record, "browser_visual_proof")
	if err != nil || len(findings) > 0 {
		return fmt.Errorf("browser visual proof contains secret-shaped data")
	}
	return nil
}

func verifyVisualExecution(record map[string]any, environment visualEnvironment) error {
	command, ok := record["command"].(map[string]any)
	if !ok || admit.KnownKeys(command, []string{"argv", "exitCode", "inputMode", "runner"}, "browser visual proof command") != nil ||
		command["inputMode"] != "materialized_snapshot" || command["runner"] != "node" || !admit.JSONNumberEquals(command["exitCode"], 0) {
		return fmt.Errorf("browser visual proof command is invalid")
	}
	if err := exactTextArray(command["argv"], visualCommandArgv, "browser visual proof command argv"); err != nil {
		return err
	}
	engines, ok := record["engines"].([]any)
	if !ok || len(engines) != len(visualEngines) {
		return fmt.Errorf("browser visual proof must record three engines")
	}
	for index, name := range visualEngines {
		engine, ok := engines[index].(map[string]any)
		if !ok || admit.KnownKeys(engine, []string{"name", "version"}, "browser visual proof engine") != nil || engine["name"] != name ||
			engine["version"] != environment.BrowserVersions[name] {
			return fmt.Errorf("browser visual proof engine versions must equal the reference environment")
		}
	}
	projects, ok := record["projects"].([]any)
	if !ok || len(projects) != len(visualEngines) {
		return fmt.Errorf("browser visual proof must record three project executions")
	}
	expected := expectedVisualProjectTests()
	for index, name := range visualEngines {
		project, ok := projects[index].(map[string]any)
		if !ok || admit.KnownKeys(project, []string{"browserName", "browserVersion", "executedTestCount", "name", "passedTestCount", "testIds"}, "browser visual proof project") != nil ||
			project["name"] != name || project["browserName"] != name || project["browserVersion"] != environment.BrowserVersions[name] {
			return fmt.Errorf("browser visual proof project identity is invalid")
		}
		testIDs, err := sortedUniqueTextArray(project["testIds"], "browser visual proof testIds")
		if err != nil {
			return err
		}
		if !slices.Equal(testIDs, expected[name]) || !admit.JSONNumberEquals(project["executedTestCount"], int64(len(testIDs))) ||
			!admit.JSONNumberEquals(project["passedTestCount"], int64(len(testIDs))) {
			return fmt.Errorf("browser visual proof project must pass exactly its expected reference comparisons and controls")
		}
	}
	return nil
}

// admitObservedCPU admits the recorded CPU: x86 instruction-set and
// hypervisor flags are booleans where observable and null otherwise; vendor,
// model and the cpuinfo features line are text or null.
func admitObservedCPU(raw any) error {
	cpu, ok := raw.(map[string]any)
	if !ok || admit.KnownKeys(cpu, []string{"avx2", "avx512f", "features", "hypervisor", "model", "vendor"}, "browser visual proof observed cpu") != nil || len(cpu) != 6 {
		return fmt.Errorf("browser visual proof must record the observed CPU")
	}
	for _, flag := range []string{"avx2", "avx512f", "hypervisor"} {
		if _, isBool := cpu[flag].(bool); cpu[flag] != nil && !isBool {
			return fmt.Errorf("browser visual proof observed CPU flags must be booleans or null")
		}
	}
	for _, field := range []string{"features", "model", "vendor"} {
		if cpu[field] != nil {
			if _, err := admit.NonEmptyText(cpu[field], "browser visual proof observed cpu "+field); err != nil {
				return err
			}
		}
	}
	return nil
}

func emptyArray(raw any) bool {
	values, ok := raw.([]any)
	return ok && len(values) == 0
}

// visualDivergentFields reads the admitted divergence list of a visual record.
func visualDivergentFields(record map[string]any) []string {
	values, _ := record["divergentFields"].([]any)
	fields := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			fields = append(fields, text)
		}
	}
	return fields
}
