package requirementdiff

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func diffScenario(id, requirementID, expected string, actions ...string) map[string]any {
	steps := make([]any, len(actions))
	for index, action := range actions {
		steps[index] = action
	}
	return map[string]any{
		"scenarioId": id, "requirementIds": []any{requirementID}, "parameters": []any{},
		"preconditions": []any{"A request is submitted."}, "actionSequence": steps,
		"expectedObservations": []any{expected}, "forbiddenObservations": []any{}, "examples": []any{},
		"vocabularyRefs": []any{}, "nonClaimRefs": []any{},
	}
}

func withScenarios(t *testing.T, context map[string]any, scenarios ...map[string]any) {
	t.Helper()
	source := context["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)
	values := make([]any, len(scenarios))
	for index, scenario := range scenarios {
		values[index] = scenario
	}
	source["scenarios"] = values
	resignContextFixture(t, context)
}

// Scenario edits used to collapse into the requirement's sourceReviewDigest;
// each scenario edit is now an entry naming the scenario and its field.
func TestBuildReportsScenarioLevelChanges(t *testing.T) {
	const pointer = "/requirementSources/consumer.requirements/scenarios/"
	baseline := contextFixture(t, "The system preserves the baseline.")
	withScenarios(t, baseline,
		diffScenario("SCN-CONSUMER-EDIT", "REQ-CONSUMER-001", "The price is 12.50.", "Request a quote."),
		diffScenario("SCN-CONSUMER-GONE", "REQ-CONSUMER-001", "It is rejected.", "Submit nothing."),
		diffScenario("SCN-CONSUMER-SAME", "REQ-CONSUMER-001", "It is unchanged.", "Wait."),
	)
	current := contextFixture(t, "The system preserves the baseline.")
	withScenarios(t, current,
		diffScenario("SCN-CONSUMER-EDIT", "REQ-CONSUMER-001", "The price is 13.50.", "Validate.", "Request a quote."),
		diffScenario("SCN-CONSUMER-NEW", "REQ-CONSUMER-001", "A price is returned.", "Request a 25 kg quote."),
		diffScenario("SCN-CONSUMER-SAME", "REQ-CONSUMER-001", "It is unchanged.", "Wait."),
	)
	output, err := Build(map[string]any{"baseContext": baseline, "currentContext": current, "diffId": "consumer.scenario.diff", "schemaVersion": json.Number("3")})
	if err != nil {
		t.Fatal(err)
	}
	want := [][3]string{
		{"requirement", "scalar_changed", "/requirements/REQ-CONSUMER-001/sourceReviewDigest"},
		{"scenario", "sequence_changed", pointer + "SCN-CONSUMER-EDIT/actionSequence"},
		{"scenario", "set_membership_changed", pointer + "SCN-CONSUMER-EDIT/expectedObservations"},
		{"scenario", "entity_removed", pointer + "SCN-CONSUMER-GONE"},
		{"scenario", "entity_added", pointer + "SCN-CONSUMER-NEW"},
	}
	changes := output["changes"].([]any)
	if len(changes) != len(want) || output["changeCount"] != len(want) {
		t.Fatalf("changes = %#v, want %d", changes, len(want))
	}
	for index, raw := range changes {
		change := raw.(map[string]any)
		got := [3]string{change["entityKind"].(string), change["changeClass"].(string), change["jsonPointer"].(string)}
		if got != want[index] {
			t.Fatalf("change %d = %v, want %v", index, got, want[index])
		}
	}
	added := changes[4].(map[string]any)
	if added["before"] != nil || added["after"].(map[string]any)["scenarioId"] != "SCN-CONSUMER-NEW" {
		t.Fatalf("added scenario values = %#v", added)
	}
	encoded, err := stablejson.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitOutput(decoded, current["snapshotId"].(string)); err != nil {
		t.Fatalf("scenario changes rejected by output admission: %v", err)
	}
	misplaced := decoded.(map[string]any)["changes"].([]any)[1].(map[string]any)
	misplaced["jsonPointer"] = pointer + "SCN-CONSUMER-OTHER/actionSequence"
	if _, err := AdmitOutput(decoded, current["snapshotId"].(string)); err == nil {
		t.Fatal("output admission accepted a scenario pointer for another entity")
	}

	scoped, err := Build(map[string]any{"baseContext": baseline, "currentContext": current, "diffId": "consumer.scenario.diff", "schemaVersion": json.Number("3"), "query": map[string]any{"requirementIds": []any{"REQ-CONSUMER-404"}}})
	if err != nil || scoped["changeCount"] != 0 {
		t.Fatalf("scenario changes escaped the requirement query: %v %v", scoped["changeCount"], err)
	}
	if _, err := Build(map[string]any{"baseContext": baseline, "currentContext": current, "diffId": "consumer.scenario.diff", "schemaVersion": json.Number("3"), "query": map[string]any{"maxChanges": json.Number("4")}}); err == nil {
		t.Fatal("scenario changes bypassed maxChanges")
	}
}

// An empty set or examples array is one value of the output union; a change
// between [] and a non-empty array must stay representable in both directions.
func TestBuildRepresentsChangesBetweenEmptyAndNonEmptyArrays(t *testing.T) {
	const scenarioPointer = "/requirementSources/consumer.requirements/scenarios/SCN-CONSUMER-EDIT/"
	// A parameterized scenario needs two examples, so the examples change also
	// moves parameters and preconditions between [] and a non-empty array.
	withExamples := func(examples ...any) map[string]any {
		scenario := diffScenario("SCN-CONSUMER-EDIT", "REQ-CONSUMER-001", "The price is 12.50.", "Request a quote.")
		if len(examples) > 0 {
			scenario["parameters"] = []any{"weight"}
			scenario["preconditions"] = []any{"A ${weight} parcel is submitted."}
		}
		scenario["examples"] = examples
		return scenario
	}
	withForbidden := func(values ...any) map[string]any {
		scenario := diffScenario("SCN-CONSUMER-EDIT", "REQ-CONSUMER-001", "The price is 12.50.", "Request a quote.")
		scenario["forbiddenObservations"] = values
		return scenario
	}
	cases := []struct {
		name, pointer, changeClass string
		empty, filled              func(t *testing.T) map[string]any
	}{
		{"requirement set", "/requirements/REQ-CONSUMER-001/sharedPremises", "set_membership_changed",
			func(t *testing.T) map[string]any { return contextFixture(t, "The system preserves the baseline.") },
			func(t *testing.T) map[string]any {
				context := contextFixture(t, "The system preserves the baseline.")
				diffSourceGroup(context)["sharedPremises"] = []any{"The service is available."}
				resignContextFixture(t, context)
				return context
			}},
		{"scenario set", scenarioPointer + "forbiddenObservations", "set_membership_changed",
			func(t *testing.T) map[string]any {
				context := contextFixture(t, "The system preserves the baseline.")
				withScenarios(t, context, withForbidden())
				return context
			},
			func(t *testing.T) map[string]any {
				context := contextFixture(t, "The system preserves the baseline.")
				withScenarios(t, context, withForbidden("An error is shown."))
				return context
			}},
		{"scenario examples", scenarioPointer + "examples", "opaque_value_changed",
			func(t *testing.T) map[string]any {
				context := contextFixture(t, "The system preserves the baseline.")
				withScenarios(t, context, withExamples())
				return context
			},
			func(t *testing.T) map[string]any {
				context := contextFixture(t, "The system preserves the baseline.")
				withScenarios(t, context, withExamples(
					map[string]any{"exampleId": "EX-25KG", "values": map[string]any{"weight": "25 kg"}},
					map[string]any{"exampleId": "EX-40KG", "values": map[string]any{"weight": "40 kg"}},
				))
				return context
			}},
	}
	for _, item := range cases {
		for _, direction := range []string{"empty to non-empty", "non-empty to empty"} {
			t.Run(item.name+" "+direction, func(t *testing.T) {
				baseline, current := item.empty(t), item.filled(t)
				if direction == "non-empty to empty" {
					baseline, current = item.filled(t), item.empty(t)
				}
				output, err := Build(map[string]any{"baseContext": baseline, "currentContext": current, "diffId": "consumer.empty.diff", "schemaVersion": json.Number("3")})
				if err != nil {
					t.Fatalf("Build() rejected its own change: %v", err)
				}
				var change map[string]any
				for _, raw := range output["changes"].([]any) {
					if candidate := raw.(map[string]any); candidate["jsonPointer"] == item.pointer {
						change = candidate
					}
				}
				if change == nil || change["changeClass"] != item.changeClass {
					t.Fatalf("changes = %#v, want %s at %s", output["changes"], item.changeClass, item.pointer)
				}
				empty := change["before"]
				if direction == "non-empty to empty" {
					empty = change["after"]
				}
				if values, ok := empty.([]any); !ok || len(values) != 0 {
					t.Fatalf("empty side = %#v, want []", empty)
				}
				encoded, err := stablejson.Marshal(output)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := AdmitOutput(decoded, current["snapshotId"].(string)); err != nil {
					t.Fatalf("output admission rejected the change: %v", err)
				}
			})
		}
	}
}

// Source admission accepts surface_id::stable_anchor scenario identities, so
// the diff's own output must readmit them as scenario entity identities.
func TestScopedScenarioIdentityRoundTripsThroughOutputAdmission(t *testing.T) {
	const scenarioID = "proofkit.test.surface::scenario_one"
	baseline := contextFixture(t, "The system preserves the baseline.")
	withScenarios(t, baseline, diffScenario(scenarioID, "REQ-CONSUMER-001", "The price is 12.50.", "Request a quote."))
	current := contextFixture(t, "The system preserves the baseline.")
	withScenarios(t, current, diffScenario(scenarioID, "REQ-CONSUMER-001", "The price is 13.50.", "Request a quote."))
	output, err := Build(map[string]any{"baseContext": baseline, "currentContext": current, "diffId": "consumer.scoped.diff", "schemaVersion": json.Number("3")})
	if err != nil {
		t.Fatal(err)
	}
	changes := output["changes"].([]any)
	scenario := changes[len(changes)-1].(map[string]any)
	if scenario["entityKind"] != "scenario" || scenario["entityId"] != scenarioID || scenario["jsonPointer"] != "/requirementSources/consumer.requirements/scenarios/"+scenarioID+"/expectedObservations" {
		t.Fatalf("scoped scenario change = %#v", scenario)
	}
	encoded, err := stablejson.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitOutput(decoded, current["snapshotId"].(string)); err != nil {
		t.Fatalf("output admission rejected a scoped scenario identity: %v", err)
	}
	// The scoped grammar belongs to scenarios only; requirements keep rule IDs.
	requirement := decoded.(map[string]any)["changes"].([]any)[0].(map[string]any)
	requirement["entityId"], requirement["jsonPointer"] = "REQ-CONSUMER-001::anchor", "/requirements/REQ-CONSUMER-001::anchor/sourceReviewDigest"
	if _, err := AdmitOutput(decoded, current["snapshotId"].(string)); err == nil || !strings.Contains(err.Error(), "entityId") {
		t.Fatalf("output admission accepted a scoped requirement identity: %v", err)
	}
}

// ScenarioComparisonFields is the scenario owner's exhaustive review
// projection. It must name every published scenario field except the identity,
// with the class the diff reports, and an edit to a field must surface as that
// field's scenario entry and no other.
func TestScenarioComparisonFieldsCoverEveryScenarioField(t *testing.T) {
	structure, err := requirementsourcecodec.InputStructure(requirementsourcemodel.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	properties := structure["properties"].(map[string]any)["scenarios"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	declared := map[string]string{}
	for name := range properties {
		switch name {
		case "scenarioId":
		case "actionSequence":
			declared[name] = "sequence"
		case "examples":
			declared[name] = "opaque"
		default:
			declared[name] = "set"
		}
	}
	t.Run("field inventory", func(t *testing.T) {
		got := map[string]string{}
		for _, field := range requirementsourceadmission.ScenarioComparisonFields(scenarioFieldFixture()) {
			if _, duplicate := got[field.Name]; duplicate {
				t.Fatalf("ScenarioComparisonFields() repeats %q", field.Name)
			}
			got[field.Name] = field.Class
		}
		if !reflect.DeepEqual(got, declared) {
			t.Fatalf("ScenarioComparisonFields() = %v, want every published scenario field except scenarioId %v", got, declared)
		}
	})

	// The model ties parameters to the ${name} references in the statements
	// and to the example value keys, so a parameter edit cannot stay alone.
	cases := []struct {
		field   string
		edit    func(scenario map[string]any)
		changed []string
	}{
		{"actionSequence", func(scenario map[string]any) {
			scenario["actionSequence"] = []any{"Validate the parcel.", "Request a quote."}
		}, []string{"actionSequence"}},
		{"examples", func(scenario map[string]any) {
			scenario["examples"] = []any{scenarioFieldExample("EX-25KG", "25 kg", ""), scenarioFieldExample("EX-40KG", "45 kg", "")}
		}, []string{"examples"}},
		{"expectedObservations", func(scenario map[string]any) {
			scenario["expectedObservations"] = []any{"A price is returned.", "A receipt is issued."}
		}, []string{"expectedObservations"}},
		{"forbiddenObservations", func(scenario map[string]any) {
			scenario["forbiddenObservations"] = []any{"An error is shown."}
		}, []string{"forbiddenObservations"}},
		{"nonClaimRefs", func(scenario map[string]any) {
			scenario["nonClaimRefs"] = []any{"NCL-CONSUMER-QUOTE"}
		}, []string{"nonClaimRefs"}},
		{"parameters", func(scenario map[string]any) {
			scenario["parameters"] = []any{"weight", "zone"}
			scenario["preconditions"] = []any{"A ${weight} parcel is submitted.", "The ${zone} zone is selected."}
			scenario["examples"] = []any{scenarioFieldExample("EX-25KG", "25 kg", "north"), scenarioFieldExample("EX-40KG", "40 kg", "south")}
		}, []string{"examples", "parameters", "preconditions"}},
		{"preconditions", func(scenario map[string]any) {
			scenario["preconditions"] = []any{"A ${weight} parcel is submitted.", "The service is available."}
		}, []string{"preconditions"}},
		{"requirementIds", func(scenario map[string]any) {
			scenario["requirementIds"] = []any{"REQ-CONSUMER-001", "REQ-CONSUMER-002"}
		}, []string{"requirementIds"}},
		{"vocabularyRefs", func(scenario map[string]any) {
			scenario["vocabularyRefs"] = []any{"TERM-QUOTE"}
		}, []string{"vocabularyRefs"}},
	}
	covered := map[string]string{}
	for _, item := range cases {
		covered[item.field] = declared[item.field]
	}
	if !reflect.DeepEqual(covered, declared) {
		t.Fatalf("changed-value cases cover %v, want every declared scenario field %v", covered, declared)
	}
	changeClassOf := map[string]string{"opaque": "opaque_value_changed", "sequence": "sequence_changed", "set": "set_membership_changed"}
	const pointer = "/requirementSources/consumer.requirements/scenarios/SCN-CONSUMER-EDIT/"
	for _, item := range cases {
		t.Run("changed "+item.field, func(t *testing.T) {
			edited := scenarioFieldFixture()
			item.edit(edited)
			baseline, current := scenarioFieldContext(t, scenarioFieldFixture()), scenarioFieldContext(t, edited)
			output, err := Build(map[string]any{"baseContext": baseline, "currentContext": current, "diffId": "consumer.scenario-field.diff", "schemaVersion": json.Number("3")})
			if err != nil {
				t.Fatalf("Build() rejected a %s edit: %v", item.field, err)
			}
			want := map[string]string{}
			for _, field := range item.changed {
				want[pointer+field] = changeClassOf[declared[field]]
			}
			got := map[string]string{}
			for _, raw := range output["changes"].([]any) {
				if change := raw.(map[string]any); change["entityKind"] == "scenario" {
					got[change["jsonPointer"].(string)] = change["changeClass"].(string)
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("scenario entries = %v, want %v", got, want)
			}
			encoded, err := stablejson.Marshal(output)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := AdmitOutput(decoded, current["snapshotId"].(string)); err != nil {
				t.Fatalf("output admission rejected the %s entry: %v", item.field, err)
			}
		})
	}
}

// scenarioFieldFixture is parameterized, so its examples can change alone.
func scenarioFieldFixture() map[string]any {
	return map[string]any{
		"scenarioId": "SCN-CONSUMER-EDIT", "requirementIds": []any{"REQ-CONSUMER-001"}, "parameters": []any{"weight"},
		"preconditions": []any{"A ${weight} parcel is submitted."}, "actionSequence": []any{"Request a quote."},
		"expectedObservations": []any{"A price is returned."}, "forbiddenObservations": []any{},
		"examples":       []any{scenarioFieldExample("EX-25KG", "25 kg", ""), scenarioFieldExample("EX-40KG", "40 kg", "")},
		"vocabularyRefs": []any{}, "nonClaimRefs": []any{},
	}
}

func scenarioFieldExample(id, weight, zone string) map[string]any {
	values := map[string]any{"weight": weight}
	if zone != "" {
		values["zone"] = zone
	}
	return map[string]any{"exampleId": id, "values": values}
}

// scenarioFieldContext declares a second requirement, a non-claim and a term
// on both sides; an unchanged anchor scenario keeps the definitions referenced.
func scenarioFieldContext(t *testing.T, edited map[string]any) map[string]any {
	t.Helper()
	context := contextFixture(t, "The system preserves the baseline.")
	group := diffSourceGroup(context)
	second := cloneRequirementRecord(t, group["members"].([]any)[0].(map[string]any))
	second["requirementId"] = "REQ-CONSUMER-002"
	group["members"] = append(group["members"].([]any), second)
	source := context["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)
	source["nonClaimDefinitions"] = []any{map[string]any{"nonClaimId": "NCL-CONSUMER-QUOTE", "statement": "A quote is not a binding offer."}}
	source["vocabulary"] = []any{map[string]any{"termId": "TERM-QUOTE", "kind": "subject", "label": "quote", "definition": "A computed shipping price."}}
	anchor := diffScenario("SCN-CONSUMER-ANCHOR", "REQ-CONSUMER-002", "A quote is shown.", "Open the quote.")
	anchor["vocabularyRefs"], anchor["nonClaimRefs"] = []any{"TERM-QUOTE"}, []any{"NCL-CONSUMER-QUOTE"}
	withScenarios(t, context, anchor, edited)
	return context
}
