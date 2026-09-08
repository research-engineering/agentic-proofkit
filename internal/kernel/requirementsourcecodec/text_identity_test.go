package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestTextRolesAndStableScenarioIdentityRoundTrip(t *testing.T) {
	const completion = "accept\nrequests\twith \"quotes\", \\ paths,\r\nUnicode \U0001f680 and \x00 data."
	const boundary = "TODO denotes caller terminology,\nnot missing behavior."
	const review = "Review TBD wording\nafter owner confirmation."
	const scenarioID = "proofkit.package-boundary.root-export-and-deep-import-denial"
	draft := testDraft()
	draft.Groups[0].Members[0].StatementCompletion = completion
	draft.NonClaimDefinitions[0].Statement = boundary
	draft.Groups[1].Members[0].Fields.Deferral.Value.ReviewCondition = review
	draft.Scenarios[0].ScenarioID = scenarioID
	model, err := requirementsourcemodel.Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Format(model)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(wire) || bytes.ContainsRune(wire, '\x00') {
		t.Fatal("formatter did not safely escape text")
	}
	parsed, err := Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	atomic := parsed.Model.Atomic()
	if atomic.Requirements[0].Invariant != "The service must "+completion ||
		atomic.NonClaimDefinitions[0].Statement != boundary ||
		atomic.Requirements[2].Deferral.ReviewCondition != review ||
		atomic.Scenarios[0].ScenarioID != scenarioID {
		t.Fatal("reader and writer agreed but lost an independently expected value")
	}
	if !projectionsEqual(parsed.Model, model) {
		t.Fatal("codec lost an atomic, layout or reference projection")
	}
	location, ok := parsed.SourceMap.Location("/groups/1/members/0/statementCompletion")
	if !ok {
		t.Fatal("multiline text lacks a lexical source location")
	}
	var replay string
	if err := json.Unmarshal(wire[location.ValueSpan.Start:location.ValueSpan.End], &replay); err != nil || replay != completion {
		t.Fatal("source-map span cannot replay the exact authored text")
	}
	second, err := Format(parsed.Model)
	if err != nil || !bytes.Equal(second, wire) {
		t.Fatal("canonical multiline representation is not idempotent")
	}
}

func TestWireTextPoliciesRejectWithoutDisclosure(t *testing.T) {
	roles := []struct {
		name string
		set  func(map[string]any, string)
	}{
		{"invariant", func(root map[string]any, s string) {
			groups := root["groups"].([]any)
			group := groups[1].(map[string]any)
			group["members"].([]any)[0].(map[string]any)["statementCompletion"] = s
		}},
		{"nonclaim", func(root map[string]any, s string) {
			root["nonClaimDefinitions"].([]any)[0].(map[string]any)["statement"] = s
		}},
		{"review", func(root map[string]any, s string) {
			group := root["groups"].([]any)[0].(map[string]any)
			fields := group["members"].([]any)[0].(map[string]any)["fields"].(map[string]any)
			fields["deferral"].(map[string]any)["reviewCondition"] = s
		}},
	}
	const secret = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	for _, role := range roles {
		t.Run(role.name, func(t *testing.T) {
			wire := mutateRoot(t, mustPayload(t), func(root map[string]any) {
				role.set(root, "token="+secret)
			})
			_, err := Parse(wire)
			if ErrorCode(err) != "invalid_text" || strings.Contains(err.Error(), secret) {
				t.Fatal("wire admission did not reject secret text without disclosure")
			}
		})
	}
}

func TestWireStableScenarioIdentityRejectsDuplicates(t *testing.T) {
	wire := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		scenarios := root["scenarios"].([]any)
		scenario := scenarios[0].(map[string]any)
		scenario["scenarioId"] = "proofkit.package-boundary.root-export-and-deep-import-denial"
		root["scenarios"] = append(scenarios, scenario)
	})
	_, err := Parse(wire)
	if ErrorCode(err) != "duplicate_id" {
		t.Fatalf("duplicate scenario wire identity was not rejected: %v", err)
	}
}
