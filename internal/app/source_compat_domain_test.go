package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	legacy "github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	codec "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	model "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestSourceCompatibilityResourceDomainsAreNotInterchangeable(t *testing.T) {
	for _, item := range []struct {
		count int
		code  string
	}{
		{4096, ""}, {16384, "expanded_item_budget_exceeded"}, {16385, "member_budget_exceeded"},
	} {
		t.Run(fmt.Sprint(item.count), func(t *testing.T) {
			data := sourceCompatJSON(t, legacy.SourceValue(sourceCompatSource(item.count)))
			if len(data) >= maxInputBytes {
				t.Fatal("source no longer fits the public byte limit; re-evaluate the domain witness")
			}
			output := runCLI(t, []string{"requirement-source-admission", "--input", "-"}, string(data))
			report := sourceCompatDecode(t, output).(map[string]any)
			if report["reportKind"] != "proofkit.requirement-source-admission" || report["state"] != "passed" || report["reportId"] != "source.compatibility" {
				t.Fatal("wrong public admission result")
			}
			source := sourceCompatAdmit(t, sourceCompatDecode(t, data))
			for range 2 {
				candidate, err := model.Normalize(sourceCompatDraft(source))
				if model.ErrorCode(err) != item.code {
					t.Fatalf("resource-domain decision changed: got %v, want %s", err, item.code)
				}
				if item.code == "" && len(candidate.Atomic().Requirements) != item.count {
					t.Fatal("candidate dropped an accepted requirement")
				}
			}
			sourceCompatRoundTrip(t, sourceCompatSource(1))
		})
	}
}

func TestSourceCompatibilityPublicIdentityAndPathsStayV1(t *testing.T) {
	source := sourceCompatSource(1)
	for _, item := range []struct{ name, field, path string }{
		{"overview/directory", "overviewPath", "docs/specs/other/overview.md"},
		{"overview/basename", "overviewPath", source.SpecPackagePath + "/summary.md"},
		{"overview/both", "overviewPath", "docs/specs/other/summary.md"},
		{"requirements/directory", "requirementsPath", "docs/specs/other/requirements.v1.json"},
		{"requirements/basename", "requirementsPath", source.SpecPackagePath + "/requirements.v2.json"},
		{"requirements/both", "requirementsPath", "docs/specs/other/requirements.v2.json"},
	} {
		t.Run(item.name, func(t *testing.T) {
			input := legacy.SourceValue(source)
			input[item.field] = item.path
			var stdout, stderr bytes.Buffer
			exit := Run(t.Context(), []string{"requirement-source-admission", "--input", "-"}, bytes.NewReader(sourceCompatJSON(t, input)), &stdout, &stderr)
			if exit != 1 || stderr.Len() != 0 {
				t.Fatalf("path contradiction exit=%d stderr=%q", exit, stderr.String())
			}
			report := sourceCompatDecode(t, stdout.Bytes()).(map[string]any)
			if report["state"] != "failed" || report["reportKind"] != "proofkit.requirement-source-admission" {
				t.Fatal("path contradiction did not produce the expected failed report")
			}
			if report["summary"].(map[string]any)["failureCount"] != json.Number("1") {
				t.Fatal("path case triggered an unrelated additional failure")
			}
		})
	}
	v1 := sourceCompatJSON(t, legacy.SourceValue(source))
	if _, err := codec.Parse(v1); err == nil {
		t.Fatal("private v2 reader accepted public v1 bytes")
	}
	candidate := sourceCompatRoundTrip(t, source)
	v2, err := codec.Format(candidate)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []any{sourceCompatDecode(t, v2), legacy.SourceValue(source)} {
		input.(map[string]any)["schemaVersion"] = json.Number("2")
		var stdout, stderr bytes.Buffer
		exit := Run(t.Context(), []string{"requirement-source-admission", "--input", "-"}, bytes.NewReader(sourceCompatJSON(t, input)), &stdout, &stderr)
		if exit != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatal("private/version-substituted input crossed the public v1 boundary")
		}
	}
	wrongVersion := sourceCompatDecode(t, v2).(map[string]any)
	wrongVersion["schemaVersion"] = json.Number("1")
	if _, err := codec.Parse(sourceCompatJSON(t, wrongVersion)); err == nil {
		t.Fatal("private grammar accepted the old identity")
	}
	runCLI(t, []string{"requirement-source-admission", "--input", "-"}, string(v1))
}

func TestSourceCompatibilityCanonicalNullIsNotInventedPresence(t *testing.T) {
	input := legacy.SourceValue(sourceCompatSource(1))
	row := input["requirements"].([]any)[0].(map[string]any)
	without := sourceCompatAdmit(t, input)
	row["deferral"] = nil
	withNull := sourceCompatAdmit(t, input)
	if !reflect.DeepEqual(without, withNull) {
		t.Fatal("canonical legacy deferral presence changed")
	}
	candidate := sourceCompatRoundTrip(t, withNull)
	fields := candidate.Layout().Groups[0].Members[0].Fields
	if !fields.Deferral.Present || fields.Deferral.Value != nil || !fields.NonClaimRefs.Present || len(fields.NonClaimRefs.Value) != 0 {
		t.Fatal("explicit candidate null/empty mapping was not retained")
	}
	row["nonClaims"] = nil
	if _, err := legacy.Evaluate(input); err == nil || !strings.Contains(err.Error(), "array") {
		t.Fatal("null collection incorrectly treated as empty")
	}
}
