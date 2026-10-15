package requirementsourcecodec

import (
	"bytes"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestParseLocatesEveryCollectedModelFault(t *testing.T) {
	repeatedID := ""
	payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		groups := root["groups"].([]any)
		first := groups[0].(map[string]any)["members"].([]any)[0].(map[string]any)
		second := groups[1].(map[string]any)["members"].([]any)[0].(map[string]any)
		repeatedID = first["requirementId"].(string)
		second["requirementId"] = repeatedID
		root["sourceId"] = ""
	})
	_, err := Parse(payload)
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("Parse() error = %v, want codec diagnostics", err)
	}
	diagnostics := typed.Diagnostics()
	got := make([][2]string, len(diagnostics))
	for index, diagnostic := range diagnostics {
		got[index] = [2]string{diagnostic.Code, diagnostic.Path}
		if diagnostic.CoordinateState != "scalar" || diagnostic.Start == nil || diagnostic.End == nil || diagnostic.Span.End <= diagnostic.Span.Start {
			t.Fatalf("diagnostic %d lacks exact coordinates: %+v", index, diagnostic)
		}
	}
	// The renamed member's former identity is gone, so its references are real
	// faults; they are reported against declared identities, not invented.
	want := [][2]string{
		{"invalid_id", "/sourceId"},
		{"duplicate_requirement_id", "/groups/1/members/0/requirementId"},
		{"dangling_requirement_ref", "/scenarios/0/requirementIds"},
		{"dangling_requirement_ref", "/derivations/0/requirementIds"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("diagnostics = %v, want %v", got, want)
	}
	duplicate := diagnostics[1]
	if !bytes.Equal(payload[duplicate.Span.Start:duplicate.Span.End], []byte(`"`+repeatedID+`"`)) {
		t.Fatalf("duplicate diagnostic span %q does not select the repeated identity", payload[duplicate.Span.Start:duplicate.Span.End])
	}
	value, valueErr := AssessValue(decodedTestValue(t, payload))
	if _, admitted := value.Summary(); valueErr == nil || valueErr.Error() != err.Error() || admitted {
		t.Fatalf("AssessValue() = %v, want the same faults without an assessment", valueErr)
	}
}

func TestShapeAdmissionCollectsIndependentFaultsWithoutCascades(t *testing.T) {
	payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		scenario := root["scenarios"].([]any)[0].(map[string]any)
		scenario["NonClaimRefs"] = scenario["nonClaimRefs"]
		delete(scenario, "nonClaimRefs")
		delete(scenario, "preconditions")
		root["groups"].([]any)[0].(map[string]any)["groupId"] = 7
	})
	_, err := Parse(payload)
	want := "invalid_type: /groups/0/groupId; noncanonical_field: /scenarios/0/nonClaimRefs; missing_field: /scenarios/0/preconditions"
	if err == nil || err.Error() != want {
		t.Fatalf("Parse() error = %v, want %q", err, want)
	}
}

// Shape faults beyond the reported bound are only counted: coordinates are
// computed once, for the reported faults, so diagnostic work stays linear in
// the source however many faults it contains. Reported coordinates equal the
// per-fault computation.
func TestManyShapeFaultsCostOneCoordinateSweep(t *testing.T) {
	const faults = 1 << 15
	payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		root["sourceNonClaims"] = []any{"PLACEHOLDER"}
	})
	payload = bytes.Replace(payload, []byte(`["PLACEHOLDER"]`), []byte("[\n"+strings.Repeat("  false,\n", faults-1)+"  false\n]"), 1)
	coordinateSweeps.Store(0)
	_, err := Parse(payload)
	sweeps := coordinateSweeps.Load()
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("Parse() error = %v, want codec diagnostics", err)
	}
	if sweeps != 1 {
		t.Fatalf("coordinate sweeps = %d, want 1 for %d faults", sweeps, faults)
	}
	diagnostics := typed.Diagnostics()
	if len(diagnostics) != requirementsourcemodel.MaxReportedValidationErrors || typed.OmittedCount() != faults-len(diagnostics) {
		t.Fatalf("described %d and omitted %d, want %d and %d", len(diagnostics), typed.OmittedCount(), requirementsourcemodel.MaxReportedValidationErrors, faults-requirementsourcemodel.MaxReportedValidationErrors)
	}
	want := []string{}
	for index, diagnostic := range diagnostics {
		path := "/sourceNonClaims/" + strconv.Itoa(index)
		want = append(want, "invalid_type: "+path)
		if diagnostic.Code != "invalid_type" || diagnostic.Path != path || string(payload[diagnostic.Span.Start:diagnostic.Span.End]) != "false" {
			t.Fatalf("diagnostic %d = %+v", index, diagnostic)
		}
		positions := positionsAt(payload, []int64{diagnostic.Span.Start, diagnostic.Span.End})
		if diagnostic.CoordinateState != "scalar" || diagnostic.Start == nil || diagnostic.End == nil || *diagnostic.Start != positions[diagnostic.Span.Start] || *diagnostic.End != positions[diagnostic.Span.End] {
			t.Fatalf("diagnostic %d coordinates = %+v, want %+v-%+v", index, diagnostic, positions[diagnostic.Span.Start], positions[diagnostic.Span.End])
		}
	}
	want = append(want, strconv.Itoa(faults-len(diagnostics))+" more")
	if err.Error() != strings.Join(want, "; ") {
		t.Fatalf("Parse() error = %q, want %q", err.Error(), strings.Join(want, "; "))
	}
	coordinateSweeps.Store(0)
	if _, valueErr := AssessValue(decodedTestValue(t, payload)); valueErr == nil || valueErr.Error() != err.Error() || coordinateSweeps.Load() != 1 {
		t.Fatalf("AssessValue() = %v after %d sweeps, want the same faults after 1", valueErr, coordinateSweeps.Load())
	}
}
