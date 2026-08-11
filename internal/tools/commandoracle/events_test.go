package commandoracle

import "testing"

func TestAdmitEventRejectsUnknownActionAndInvalidAuxiliaryTypes(t *testing.T) {
	for _, testCase := range []struct {
		name string
		line string
		want string
	}{
		{name: "unknown action", line: `{"Action":"counterfeit","Package":"example.test/p"}`, want: "event.action_unknown"},
		{name: "elapsed string", line: `{"Action":"start","Elapsed":"0","Package":"example.test/p"}`, want: "event.field_type_invalid"},
		{name: "output object", line: `{"Action":"output","Output":{},"Package":"example.test/p"}`, want: "event.field_type_invalid"},
		{name: "time number", line: `{"Action":"start","Package":"example.test/p","Time":1}`, want: "event.field_type_invalid"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := admitEvent([]byte(testCase.line)); DecisionID(err) != testCase.want {
				t.Fatalf("admitEvent() error = %v, want %s", err, testCase.want)
			}
		})
	}
}

func TestEventLedgerRejectsPackageAndTestActionContextDrift(t *testing.T) {
	candidates := syntheticCandidates()
	imports := map[string]string{"./internal/sample": "example.test/proofkit/internal/sample"}
	for _, testCase := range []struct {
		name  string
		event testEvent
		want  string
	}{
		{name: "package run", event: testEvent{Action: "run", Package: imports["./internal/sample"]}, want: "event.package_action_invalid"},
		{name: "test start", event: testEvent{Action: "start", Package: imports["./internal/sample"], Test: "TestShared"}, want: "event.selected_test_action_invalid"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ledger, err := newEventLedger(candidates, imports)
			if err != nil {
				t.Fatal(err)
			}
			if err := ledger.observe(testEvent{Action: "start", Package: imports["./internal/sample"]}); err != nil {
				t.Fatal(err)
			}
			if err := ledger.observe(testCase.event); DecisionID(err) != testCase.want {
				t.Fatalf("observe() error = %v, want %s", err, testCase.want)
			}
		})
	}
}
