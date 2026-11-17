package gradualadoption

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestBootstrapMaterializationInputIsDefensive(t *testing.T) {
	input := validBootstrapInput()
	result, err := BuildBootstrapResult(input)
	if err != nil {
		t.Fatal(err)
	}
	before, err := result.MaterializationInput()
	if err != nil || !reflect.DeepEqual(before, input) {
		t.Fatalf("canonical source differs from admitted input: %v", err)
	}
	projection, err := result.MaterializationInput()
	if err != nil {
		t.Fatal(err)
	}
	projection["module"].(map[string]any)["requirementIds"].([]any)[0] = "REQ-CHANGED"
	result.Payloads["adoptionProfile"].(map[string]any)["budget"].(map[string]any)["profileLines"] = json.Number("999")
	result.Payloads["witnessPlanInput"].(map[string]any)["commands"].([]any)[0].(map[string]any)["argv"].([]any)[0] = "changed"
	input["repository"].(map[string]any)["profilePath"] = "inputs/changed.json"
	after, err := result.MaterializationInput()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("caller, projection or exported payload mutation changed canonical input")
	}
	if _, leaked := result.JSONValue()["materialization"]; leaked {
		t.Fatal("private canonical storage leaked into public JSON")
	}
}

func TestBootstrapUnadmittedResultRefusesMaterialization(t *testing.T) {
	result := BootstrapResult{}
	if value, err := BootstrapMaterializationManifest(result); err == nil || value != nil {
		t.Fatal("unadmitted result manufactured a canonical manifest")
	}
	if value, err := result.MaterializationInput(); err == nil || value != nil {
		t.Fatal("unadmitted result manufactured a canonical input")
	}
}

func TestBootstrapManifestIgnoresPublishedMutation(t *testing.T) {
	for _, route := range []string{"json-payload", "exported-payload", "json-planned-file", "exported-planned-file", "exported-next-command", "exported-record", "json-record"} {
		t.Run(route, func(t *testing.T) {
			result, err := BuildBootstrapResult(validBootstrapInput())
			if err != nil || result.Record.State != "passed" {
				t.Fatalf("baseline bootstrap failed: %v", err)
			}
			before, err := BootstrapMaterializationManifest(result)
			if err != nil {
				t.Fatal(err)
			}
			operations := result.PreparedCommands()
			projection := result.JSONValue()
			switch route {
			case "json-payload":
				projection["payloads"].(map[string]any)["adoptionGuidance"].(map[string]any)["agentGuidance"].(map[string]any)["proofkitCommands"].(map[string]any)["witness-plan"] = "inputs/other.json"
			case "exported-payload":
				result.Payloads["adoptionGuidance"].(map[string]any)["agentGuidance"].(map[string]any)["proofkitCommands"].(map[string]any)["witness-plan"] = "inputs/other.json"
			case "json-planned-file":
				projection["plannedFiles"].([]any)[0].(map[string]any)["path"] = "inputs/other.json"
			case "exported-planned-file":
				result.PlannedFiles[0].(map[string]any)["path"] = "inputs/other.json"
			case "exported-next-command":
				result.NextCommands[0] = "changed display"
			case "exported-record":
				result.Record.Summary["payloadCount"] = 100
				result.Record.ReportID = "report.changed"
			case "json-record":
				projection["report"].(map[string]any)["summary"].(map[string]any)["payloadCount"] = 100
			}
			after, err := BootstrapMaterializationManifest(result)
			if err != nil {
				return // Explicit refusal is also a valid immutable-record boundary.
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("published mutation changed future canonical manifest")
			}
			if !reflect.DeepEqual(operations, result.PreparedCommands()) {
				t.Fatal("projection changed prepared operations")
			}
		})
	}
}

func TestBootstrapManifestProjectionDoesNotOwnFutureManifest(t *testing.T) {
	result, err := BuildBootstrapResult(validBootstrapInput())
	if err != nil {
		t.Fatal(err)
	}
	before, err := BootstrapMaterializationManifest(result)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := BootstrapMaterializationManifest(result)
	if err != nil {
		t.Fatal(err)
	}
	projection["files"].([]any)[0].(map[string]any)["content"] = "changed"
	projection["sourceReport"].(map[string]any)["state"] = "changed"
	projection["nextCommands"].([]any)[0] = "changed"
	after, err := BootstrapMaterializationManifest(result)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("manifest projection changed private materialization state")
	}
}
