package requirementsourcemodel

import (
	"strings"
	"testing"
)

func TestNormalizePreservesTextBySemanticRole(t *testing.T) {
	const completion = "accept\nrequests\twith \"quoted\" \\ values,\r\nUnicode \U0001f680 and \x00 data."
	const boundary = "TODO is a caller label,\nnot an implementation claim."
	const review = "Review the TBD policy\nafter the owner meeting."
	draft := validDraft()
	draft.Groups[0].Members[0].StatementCompletion = completion
	draft.NonClaimDefinitions[0].Statement = boundary
	draft.Groups[1].Members[0].Fields.Deferral.Value.ReviewCondition = review
	model, err := Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}
	atomic := model.Atomic()
	if atomic.Requirements[0].Invariant != "The service must "+completion {
		t.Fatal("normalization changed invariant bytes")
	}
	if atomic.NonClaimDefinitions[0].Statement != boundary || atomic.Requirements[2].Deferral.ReviewCondition != review {
		t.Fatal("operational text was rejected or rewritten as an invariant")
	}
	for _, group := range model.Layout().Groups {
		for _, member := range group.Members {
			if member.RequirementID == "REQ-MODEL-001" && member.StatementCompletion != completion {
				t.Fatal("layout lost original completion bytes")
			}
		}
	}
}

func TestNormalizeTextSafetyRemainsRoleIndependent(t *testing.T) {
	roles := []struct {
		name string
		set  func(*Draft, string)
	}{
		{"invariant", func(d *Draft, s string) { d.Groups[0].Members[0].StatementCompletion = s }},
		{"nonclaim", func(d *Draft, s string) { d.NonClaimDefinitions[0].Statement = s }},
		{"review", func(d *Draft, s string) { d.Groups[1].Members[0].Fields.Deferral.Value.ReviewCondition = s }},
	}
	for _, role := range roles {
		for _, value := range []struct{ name, text string }{
			{"secret", "token=ghp_0123456789abcdefghijklmnopqrstuvwxyz"},
			{"invalid_utf8", "invalid-\xff-text"},
			{"outer_space", " untrimmed caller text "},
		} {
			t.Run(role.name+"/"+value.name, func(t *testing.T) {
				draft := validDraft()
				role.set(&draft, value.text)
				_, err := Normalize(draft)
				if ErrorCode(err) != "invalid_text" {
					t.Fatalf("error code = %q, want invalid_text", ErrorCode(err))
				}
				if strings.Contains(err.Error(), value.text) {
					t.Fatal("diagnostic disclosed caller text")
				}
			})
		}
	}
	for _, placeholder := range []string{"TODO", "fixme", "TBD"} {
		draft := validDraft()
		draft.Groups[0].Members[0].StatementCompletion = "accept " + placeholder + " requests."
		if _, err := Normalize(draft); ErrorCode(err) != "placeholder_text" {
			t.Fatalf("unfinished invariant accepted: code=%q", ErrorCode(err))
		}
	}
}

func TestNormalizeScenarioIdentityUsesStableRuleDomain(t *testing.T) {
	const id = "proofkit.package-boundary.root-export-and-deep-import-denial"
	draft := validDraft()
	draft.Scenarios[0].ScenarioID = id
	model, err := Normalize(draft)
	if err != nil {
		t.Fatal(err)
	}
	if got := model.Atomic().Scenarios[0].ScenarioID; got != id {
		t.Fatalf("scenario ID changed to %q", got)
	}
	edges := 0
	for _, edge := range model.References().Edges {
		if edge.From.Kind == EntityScenario {
			if edge.From.ID != id {
				t.Fatal("scenario reference origin was renamed")
			}
			edges++
		}
	}
	if edges != 3 {
		t.Fatalf("scenario reference edges = %d, want 3", edges)
	}
	draft.Scenarios = append(draft.Scenarios, draft.Scenarios[0])
	if _, err := Normalize(draft); ErrorCode(err) != "duplicate_id" {
		t.Fatalf("duplicate scenario code = %q", ErrorCode(err))
	}
	draft = validDraft()
	draft.Scenarios[0].ScenarioID = "invalid scenario identity"
	if _, err := Normalize(draft); ErrorCode(err) != "invalid_id" {
		t.Fatalf("invalid scenario code = %q", ErrorCode(err))
	}
}
