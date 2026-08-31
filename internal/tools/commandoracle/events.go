package commandoracle

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

const (
	maxEventLineBytes = 1 << 20
	maxEventBytes     = 64 << 20
	maxEventCount     = 2_000_000
)

type testEvent struct {
	Action      string
	FailedBuild string
	Key         string
	Package     string
	Test        string
	Value       string
}

type selectedTestKey struct {
	Package string
	Test    string
}

type selectedTestState struct {
	attributes map[string]struct{}
	passed     bool
	paused     bool
	run        bool
}

type descendantTestState struct {
	passed bool
	paused bool
	run    bool
}

type packageEventState struct {
	passed  bool
	started bool
}

type eventLedger struct {
	expectedAttributes map[selectedTestKey]map[string]struct{}
	descendants        map[selectedTestKey]*descendantTestState
	packages           map[string]*packageEventState
	tests              map[selectedTestKey]*selectedTestState
}

func newEventLedger(candidates []app.CommandCoverageOracleCandidate, packageImports map[string]string) (*eventLedger, error) {
	ledger := &eventLedger{
		expectedAttributes: map[selectedTestKey]map[string]struct{}{},
		descendants:        map[selectedTestKey]*descendantTestState{},
		packages:           map[string]*packageEventState{},
		tests:              map[selectedTestKey]*selectedTestState{},
	}
	for _, candidate := range candidates {
		packageImport, ok := packageImports[candidate.PackagePath]
		if !ok {
			return nil, decision("join.package_import_missing")
		}
		key := selectedTestKey{Package: packageImport, Test: candidate.TestName}
		if _, ok := ledger.tests[key]; !ok {
			ledger.tests[key] = &selectedTestState{attributes: map[string]struct{}{}}
			ledger.expectedAttributes[key] = map[string]struct{}{}
		}
		if _, exists := ledger.expectedAttributes[key][candidate.SourceMarker]; exists {
			return nil, decision("join.attribute_identity_duplicate")
		}
		ledger.expectedAttributes[key][candidate.SourceMarker] = struct{}{}
		if _, exists := ledger.packages[packageImport]; !exists {
			ledger.packages[packageImport] = &packageEventState{}
		}
	}
	return ledger, nil
}

func parseEvents(reader io.Reader, ledger *eventLedger) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), maxEventLineBytes)
	totalBytes := 0
	eventCount := 0
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		totalBytes += len(line) + 1
		eventCount++
		if totalBytes > maxEventBytes {
			return decision("event.total_bytes_exceeded")
		}
		if eventCount > maxEventCount {
			return decision("event.count_exceeded")
		}
		event, err := admitEvent(line)
		if err != nil {
			return err
		}
		if err := ledger.observe(event); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return decision("event.line_invalid_or_oversized")
	}
	return nil
}

func admitEvent(line []byte) (testEvent, error) {
	raw, err := admission.DecodeJSON(bytes.NewReader(line), maxEventLineBytes)
	if err != nil {
		return testEvent{}, decision("event.json_invalid")
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return testEvent{}, decision("event.object_required")
	}
	if err := admit.KnownKeys(record, []string{"Action", "Elapsed", "FailedBuild", "Key", "Output", "Package", "Test", "Time", "Value"}, "go test event"); err != nil {
		return testEvent{}, decision("event.unknown_field")
	}
	action, ok := record["Action"].(string)
	if !ok || strings.TrimSpace(action) == "" {
		return testEvent{}, decision("event.action_invalid")
	}
	if !validEventAction(action) {
		return testEvent{}, decision("event.action_unknown")
	}
	for _, key := range []string{"FailedBuild", "Key", "Package", "Test", "Value"} {
		if value, exists := record[key]; exists {
			if _, ok := value.(string); !ok {
				return testEvent{}, decision("event.field_type_invalid")
			}
		}
	}
	for _, key := range []string{"Output", "Time"} {
		if value, exists := record[key]; exists {
			if _, ok := value.(string); !ok {
				return testEvent{}, decision("event.field_type_invalid")
			}
		}
	}
	if value, exists := record["Elapsed"]; exists {
		if _, ok := value.(json.Number); !ok {
			return testEvent{}, decision("event.field_type_invalid")
		}
	}
	return testEvent{
		Action:      action,
		FailedBuild: stringField(record, "FailedBuild"),
		Key:         stringField(record, "Key"),
		Package:     stringField(record, "Package"),
		Test:        stringField(record, "Test"),
		Value:       stringField(record, "Value"),
	}, nil
}

func stringField(record map[string]any, key string) string {
	value, _ := record[key].(string)
	return value
}

func validEventAction(action string) bool {
	switch action {
	case "attr", "bench", "cont", "fail", "output", "pass", "pause", "run", "skip", "start":
		return true
	default:
		return false
	}
}

func (ledger *eventLedger) observe(event testEvent) error {
	if !validEventAction(event.Action) {
		return decision("event.action_unknown")
	}
	key := selectedTestKey{Package: event.Package, Test: event.Test}
	state, selected := ledger.tests[key]
	packageState, expectedPackage := ledger.packages[event.Package]
	if !expectedPackage {
		return decision("event.package_unknown")
	}
	if event.Test == "" && event.Action == "start" {
		if packageState.started || packageState.passed {
			return decision("event.package_start_duplicate")
		}
		packageState.started = true
		return nil
	}
	if !packageState.started {
		return decision("event.package_not_started")
	}
	if packageState.passed {
		return decision("event.package_already_passed")
	}
	descendant := ledger.selectedDescendant(key)
	if event.Test == "" {
		switch event.Action {
		case "fail", "output", "pass", "skip":
		default:
			return decision("event.package_action_invalid")
		}
	}
	if event.Action == "attr" && event.Key == commandcoverage.ExecutionAttributeKey {
		if !selected {
			return decision("event.reserved_attribute_unknown_test")
		}
		if !state.run || state.passed {
			return decision("event.reserved_attribute_wrong_order")
		}
		if _, expected := ledger.expectedAttributes[key][event.Value]; !expected {
			return decision("event.reserved_attribute_unknown_value")
		}
		if _, duplicate := state.attributes[event.Value]; duplicate {
			return decision("event.reserved_attribute_duplicate")
		}
		state.attributes[event.Value] = struct{}{}
		return nil
	}
	if event.Test != "" && !selected && !descendant {
		return decision("event.unselected_test_observed")
	}
	if ledger.selectedDescendantFailedOrSkipped(event) {
		return decision("event.selected_descendant_failed_or_skipped")
	}
	if descendant {
		parent := ledger.selectedParent(key)
		if parent == nil || !parent.run || parent.passed {
			return decision("event.selected_descendant_wrong_order")
		}
		descendantState := ledger.descendants[key]
		switch event.Action {
		case "run":
			if descendantState != nil {
				return decision("event.selected_descendant_run_duplicate")
			}
			ledger.descendants[key] = &descendantTestState{run: true}
		case "pause":
			if descendantState == nil || !descendantState.run || descendantState.paused || descendantState.passed {
				return decision("event.selected_descendant_pause_wrong_order")
			}
			descendantState.paused = true
		case "cont":
			if descendantState == nil || !descendantState.run || !descendantState.paused || descendantState.passed {
				return decision("event.selected_descendant_cont_wrong_order")
			}
			descendantState.paused = false
		case "pass":
			if descendantState == nil || !descendantState.run || descendantState.paused || descendantState.passed {
				return decision("event.selected_descendant_pass_wrong_order")
			}
			descendantState.passed = true
		case "attr", "output":
			if descendantState == nil || !descendantState.run || descendantState.passed {
				return decision("event.selected_descendant_auxiliary_wrong_order")
			}
		case "bench", "start":
			return decision("event.selected_descendant_action_invalid")
		}
		return nil
	}
	if selected {
		switch event.Action {
		case "run":
			if state.run || state.passed {
				return decision("event.test_run_duplicate")
			}
			state.run = true
		case "pass":
			if !state.run || state.paused || state.passed || !ledger.descendantsPassed(key) {
				return decision("event.test_pass_wrong_order")
			}
			if len(state.attributes) != len(ledger.expectedAttributes[key]) {
				return decision("event.test_pass_missing_attributes")
			}
			state.passed = true
		case "fail", "skip":
			return decision("event.selected_test_failed_or_skipped")
		case "pause":
			if !state.run || state.paused || state.passed {
				return decision("event.test_pause_wrong_order")
			}
			state.paused = true
		case "cont":
			if !state.run || !state.paused || state.passed {
				return decision("event.test_cont_wrong_order")
			}
			state.paused = false
		case "attr", "output":
			if !state.run || state.passed {
				return decision("event.selected_test_auxiliary_wrong_order")
			}
		case "bench", "start":
			return decision("event.selected_test_action_invalid")
		}
	}
	if event.Test == "" {
		switch event.Action {
		case "pass":
			if !ledger.packageTestsPassed(event.Package) {
				return decision("event.package_pass_before_tests")
			}
			packageState.passed = true
		case "fail", "skip":
			return decision("event.selected_package_failed_or_skipped")
		}
	}
	return nil
}

func (ledger *eventLedger) descendantsPassed(parent selectedTestKey) bool {
	for key, state := range ledger.descendants {
		if key.Package == parent.Package && strings.HasPrefix(key.Test, parent.Test+"/") && !state.passed {
			return false
		}
	}
	return true
}

func (ledger *eventLedger) selectedDescendant(key selectedTestKey) bool {
	return ledger.selectedParent(key) != nil
}

func (ledger *eventLedger) selectedParent(key selectedTestKey) *selectedTestState {
	for selectedKey, state := range ledger.tests {
		if key.Package == selectedKey.Package && strings.HasPrefix(key.Test, selectedKey.Test+"/") {
			return state
		}
	}
	return nil
}

func (ledger *eventLedger) packageTestsPassed(packageImport string) bool {
	for key, state := range ledger.tests {
		if key.Package == packageImport && !state.passed {
			return false
		}
	}
	return true
}

func (ledger *eventLedger) selectedDescendantFailedOrSkipped(event testEvent) bool {
	if event.Action != "fail" && event.Action != "skip" {
		return false
	}
	for key := range ledger.tests {
		if event.Package == key.Package && strings.HasPrefix(event.Test, key.Test+"/") {
			return true
		}
	}
	return false
}

func (ledger *eventLedger) finalize() error {
	keys := make([]selectedTestKey, 0, len(ledger.tests))
	for key := range ledger.tests {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		return keys[left].Package+"\x00"+keys[left].Test < keys[right].Package+"\x00"+keys[right].Test
	})
	for _, key := range keys {
		state := ledger.tests[key]
		if !state.run {
			return decision("event.test_run_missing")
		}
		if !state.passed {
			return decision("event.test_pass_missing")
		}
		if len(state.attributes) != len(ledger.expectedAttributes[key]) {
			return decision("event.attribute_closure_missing")
		}
	}
	for _, state := range ledger.descendants {
		if !state.run || state.paused || !state.passed {
			return decision("event.selected_descendant_incomplete")
		}
	}
	packages := make([]string, 0, len(ledger.packages))
	for packageImport := range ledger.packages {
		packages = append(packages, packageImport)
	}
	sort.Strings(packages)
	for _, packageImport := range packages {
		if !ledger.packages[packageImport].started {
			return decision("event.package_start_missing")
		}
		if !ledger.packages[packageImport].passed {
			return decision("event.package_pass_missing")
		}
	}
	return nil
}
