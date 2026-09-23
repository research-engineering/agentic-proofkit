package requirementbinding

import (
	"encoding/json"
	"reflect"
	"testing"
)

// This expected wire contract is authored independently of jsonshape. A runtime
// fallback must not hide missing constraints in the consumer-facing projection.
func TestInputStructureExactProjection(t *testing.T) {
	const expected = `{
	  "$schema":"https://json-schema.org/draft/2020-12/schema",
	  "type":"object", "additionalProperties":false,
	  "required":["bindingId","bindings","nonClaims","requirements","schemaVersion","witnessCommands"],
	  "properties":{
	    "bindingId":{"type":"string"},
	    "bindings":{"type":"array","items":{
	      "type":"object","additionalProperties":false,
	      "required":["commandIds","environmentClasses","requirementId","scenarioId","witnessId","witnessKind","witnessPath"],
	      "properties":{
	        "commandIds":{"type":"array","items":{"type":"string"}},
	        "environmentClasses":{"type":"array","items":{"type":"string"}},
	        "requirementId":{"type":"string"},"scenarioId":{"type":"string"},
	        "witnessId":{"type":"string"},
	        "witnessKind":{"type":"string","enum":["contract","falsification","technical"]},
	        "witnessPath":{"type":"string"},
	        "witnessSelectors":{"anyOf":[{"type":"null"},{
	          "type":"array","minItems":1,"items":{
	            "type":"object","additionalProperties":false,"required":["command","selector"],
	            "properties":{"command":{"type":"string"},"selector":{"type":"string"}}
	          }
	        }]}
	      }
	    }},
	    "nonClaims":{"type":"array","items":{"type":"string"}},
	    "requirements":{"type":"array","items":{
	      "type":"object","additionalProperties":false,
	      "required":["claimLevel","nonClaims","ownerId","proofState","requirementId","specPath"],
	      "properties":{
	        "claimLevel":{"type":"string","enum":["advisory","blocking","deferred"]},
	        "nonClaims":{"type":"array","items":{"type":"string"}},
	        "ownerId":{"type":"string"},
	        "proofState":{"type":"string","enum":["explicitly_deferred","not_bound","witness_backed"]},
	        "requirementId":{"type":"string"},"specPath":{"type":"string"}
	      }
	    }},
	    "schemaVersion":{"type":"integer","const":1,"x-proofkit-number-encoding":"canonical-int64"},
	    "selection":{"anyOf":[{"type":"null"},{
	      "type":"object","additionalProperties":false,"properties":{
	        "changedPaths":{"anyOf":[{"type":"null"},{"type":"array","items":{"type":"string"}}]},
	        "ownerIds":{"anyOf":[{"type":"null"},{"type":"array","items":{"type":"string"}}]},
	        "requirementIds":{"anyOf":[{"type":"null"},{"type":"array","items":{"type":"string"}}]}
	      }
	    }]},
	    "witnessCommands":{"type":"array","items":{
	      "type":"object","additionalProperties":false,"required":["command","commandId"],
	      "properties":{
	        "command":{"type":"string"},"commandId":{"type":"string"},
	        "environmentClass":{"type":"string"},
	        "environmentClasses":{"type":"array","minItems":1,"items":{"type":"string"}}
	      },
	      "oneOf":[{"required":["environmentClass"]},{"required":["environmentClasses"]}]
	    }}
	  }
	}`
	encoded, err := json.Marshal(InputStructure())
	if err != nil {
		t.Fatal(err)
	}
	var got, want any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("input structure differs from the independent complete wire expectation")
	}
}

func TestInputStructureAdmitsOptionalPresenceVariants(t *testing.T) {
	for _, change := range []func(map[string]any){
		func(raw map[string]any) { delete(raw, "selection") },
		func(raw map[string]any) { raw["selection"] = nil },
		func(raw map[string]any) { raw["selection"] = map[string]any{} },
		func(raw map[string]any) {
			raw["selection"] = map[string]any{"changedPaths": nil, "ownerIds": nil, "requirementIds": nil}
		},
		func(raw map[string]any) { raw["bindings"].([]any)[0].(map[string]any)["witnessSelectors"] = nil },
		func(raw map[string]any) {
			command := raw["witnessCommands"].([]any)[0].(map[string]any)
			delete(command, "environmentClass")
			command["environmentClasses"] = []any{"local-go"}
		},
	} {
		raw := validRequirementBindingInput()
		change(raw)
		got, err := bindingInputShape.Admit(raw, "input")
		if err != nil || !reflect.DeepEqual(got, raw) {
			t.Fatalf("structural snapshot changed an optional presence variant: %v", err)
		}
	}
}
