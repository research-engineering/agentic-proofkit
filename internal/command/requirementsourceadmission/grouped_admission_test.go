package requirementsourceadmission

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
)

func TestGroupedSourceFailureExposesOnlyAdmittedSummary(t *testing.T) {
	input := validSource()
	fields := sourceMember(input, 0)["fields"].(map[string]any)
	fields["proofBindingRefs"] = []any{}
	policy := fields["updatePolicy"].(map[string]any)
	policy["requiresImpactDeclaration"], policy["requiresProofBindingReview"] = false, false
	result, err := Evaluate(input)
	if err != nil || result.ExitCode != 1 || result.Report.State != "failed" || len(result.Failures) != 3 {
		t.Fatalf("policy occurrences lost: result=%#v error=%v", result, err)
	}
	if result.Report.SchemaVersion != 2 || result.Report.ReportID != "proofkit.test.requirements" ||
		result.Summary.RequirementCount != 1 || result.Summary.ActiveRequirementCount != 1 || result.Summary.BlockingRequirementCount != 1 {
		t.Fatal("failed source lost admitted identity/counts")
	}
	for _, source := range []Source{result.Source, {}} {
		if _, ok := source.Model(); ok {
			t.Fatal("failed/zero source exposed a model")
		}
		if value, err := SourceValue(source); err == nil || value != nil {
			t.Fatal("failed/zero source exposed a full value")
		}
		if value, err := SourceBytes(source); err == nil || value != nil {
			t.Fatal("failed/zero source exposed source bytes")
		}
		if source.RequirementCount() != 0 || len(source.Requirements()) != 0 {
			t.Fatal("failed source exposed policy-invalid requirements")
		}
	}
	fields["riskClass"] = 42
	invalid, err := Evaluate(input)
	if err == nil || !reflect.DeepEqual(invalid, Result{}) {
		t.Fatal("structural failure exposed partial report operands")
	}
}

func TestGroupedSourceProjectionReentersOwnerWithoutLoss(t *testing.T) {
	result, err := Evaluate(validSource())
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("source: %v %v", err, result.Failures)
	}
	value, err := SourceValue(result.Source)
	if err != nil {
		t.Fatal(err)
	}
	if value["schemaVersion"] != json.Number("2") || value["kind"] != "proofkit.requirement-source" {
		t.Fatal("new source semantics retained old identity")
	}
	for _, forbidden := range []string{"requirements", "overviewPath", "requirementsPath", "nonClaims"} {
		if _, exists := value[forbidden]; exists {
			t.Fatalf("whole source retained old field %s", forbidden)
		}
	}
	encoded, err := SourceBytes(result.Source)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := requirementsourcecodec.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	model, ok := result.Source.Model()
	if !ok || !reflect.DeepEqual(model.Atomic(), parsed.Model.Atomic()) || !reflect.DeepEqual(model.Layout(), parsed.Model.Layout()) || !reflect.DeepEqual(model.References(), parsed.Model.References()) {
		t.Fatal("source bytes lost an admitted owner projection")
	}
	projected, err := json.Marshal(result.Source.Requirements())
	if err != nil {
		t.Fatal(err)
	}
	native, err := json.Marshal(model.Requirements())
	if err != nil {
		t.Fatal(err)
	}
	var projectedFields, nativeFields any
	if err := json.Unmarshal(projected, &projectedFields); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(native, &nativeFields); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(projectedFields, nativeFields) {
		t.Fatal("command atomic projection omitted or changed a model field")
	}
	readmitted, err := Evaluate(value)
	if err != nil || readmitted.ExitCode != 0 || !reflect.DeepEqual(result.Report, readmitted.Report) {
		t.Fatalf("source value round trip changed report: %v", err)
	}
	value["schemaVersion"] = json.Number("1")
	if _, err := Evaluate(value); err == nil {
		t.Fatal("old identity admitted grouped source semantics")
	}
	if _, err := Evaluate(map[string]any{"schemaVersion": json.Number("1"), "requirements": []any{}}); err == nil {
		t.Fatal("old whole source reader remains active")
	}
}
