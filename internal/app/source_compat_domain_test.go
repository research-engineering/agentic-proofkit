package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	sourceowner "github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	model "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestSourceCompatibilityPublicResourceDomain(t *testing.T) {
	for _, item := range []struct {
		count int
		code  string
	}{
		{4096, ""}, {4097, ""}, {16384, "expanded_item_budget_exceeded"}, {16385, "member_budget_exceeded"},
	} {
		t.Run(fmt.Sprint(item.count), func(t *testing.T) {
			source := sourceCompatSource(item.count)
			data := sourceCompatJSON(t, sourceCompatValue(source))
			if len(data) >= maxInputBytes {
				t.Fatal("source no longer fits the public byte limit; re-evaluate the domain witness")
			}
			var stdout, stderr bytes.Buffer
			exit := Run(t.Context(), []string{"requirement-source-admission", "--input", "-"}, bytes.NewReader(data), &stdout, &stderr)
			if item.code == "" {
				if exit != 0 || stderr.Len() != 0 {
					t.Fatalf("accepted domain rejected: exit=%d stderr=%s", exit, stderr.String())
				}
				report := sourceCompatDecode(t, stdout.Bytes()).(map[string]any)
				if report["reportKind"] != "proofkit.requirement-source-admission" || report["state"] != "passed" || report["reportId"] != "source.compatibility" || report["schemaVersion"] != json.Number("2") {
					t.Fatal("wrong public admission result")
				}
			} else if exit != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatal("out-of-budget source did not fail as an input error")
			}
			candidate, err := model.Normalize(sourceCompatDraft(source))
			if model.ErrorCode(err) != item.code {
				t.Fatalf("resource-domain decision changed: got %v, want %s", err, item.code)
			}
			if item.code == "" && len(candidate.Atomic().Requirements) != item.count {
				t.Fatal("candidate dropped an accepted requirement")
			}
		})
	}
}

func TestSourceCompatibilityPublicIdentityAndDerivedPaths(t *testing.T) {
	source := sourceCompatSource(1)
	admitted := sourceCompatAdmit(t, sourceCompatValue(source))
	if admitted.OverviewPath() != source.OverviewPath() || admitted.RequirementsPath() != source.RequirementsPath() {
		t.Fatal("derived public source paths changed")
	}
	for _, item := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"old_marker", func(input map[string]any) { input["schemaVersion"] = json.Number("1") }},
		{"overview_override", func(input map[string]any) { input["overviewPath"] = source.OverviewPath() }},
		{"requirements_override", func(input map[string]any) { input["requirementsPath"] = source.RequirementsPath() }},
	} {
		t.Run(item.name, func(t *testing.T) {
			input := sourceCompatValue(source)
			item.mutate(input)
			sourceCompatRejectCLI(t, input)
		})
	}
	// The predecessor remains only a rejection fixture, not a second public reader.
	for _, version := range []string{"1", "2"} {
		input := map[string]any{
			"schemaVersion": json.Number(version), "sourceId": source.SourceID(), "specPackagePath": source.SpecPackagePath(),
			"overviewPath": source.OverviewPath(), "requirementsPath": source.SpecPackagePath() + "/requirements.v1.json",
			"nonClaims": []any{"No execution is asserted."}, "requirements": []any{},
		}
		sourceCompatRejectCLI(t, input)
	}
	sourceCompatRoundTrip(t, source)
	runCLI(t, []string{"requirement-source-admission", "--input", "-"}, string(sourceCompatJSON(t, sourceCompatValue(source))))
}

func sourceCompatRejectCLI(t testing.TB, input any) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), []string{"requirement-source-admission", "--input", "-"}, bytes.NewReader(sourceCompatJSON(t, input)), &stdout, &stderr)
	if exit != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("invalid source crossed the public boundary: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestSourceCompatibilityCanonicalNullIsNotInventedPresence(t *testing.T) {
	input := sourceCompatValue(sourceCompatSource(1))
	group := input["groups"].([]any)[0].(map[string]any)
	row := group["members"].([]any)[0].(map[string]any)["fields"].(map[string]any)
	withNull := sourceCompatAdmit(t, input)
	candidate, ok := withNull.Model()
	if !ok {
		t.Fatal("admitted source has no model")
	}
	fields := candidate.Layout().Groups[0].Members[0].Fields
	if !fields.Deferral.Present || fields.Deferral.Value != nil || !fields.NonClaimRefs.Present || len(fields.NonClaimRefs.Value) != 0 {
		t.Fatal("explicit null/empty ownership was not retained")
	}
	delete(row, "deferral")
	if _, err := sourceowner.Evaluate(input); err == nil {
		t.Fatal("unowned deferral was treated as explicitly owned null")
	}
	row["deferral"] = nil
	row["nonClaims"] = nil
	sourceCompatRejectCLI(t, input)
}
