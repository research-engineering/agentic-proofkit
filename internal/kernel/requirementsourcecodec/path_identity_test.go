package requirementsourcecodec

import (
	"strings"
	"testing"

	model "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestModelPathAdmissionIsClosedUnderWireEncoding(t *testing.T) {
	for _, role := range []struct {
		name string
		set  func(*model.Draft, string)
	}{
		{"source", func(d *model.Draft, s string) { d.SpecPackagePath = s }},
		{"derivation", func(d *model.Draft, s string) { d.Derivations[0].SourceRef.Path = s }},
		{"member binding", func(d *model.Draft, s string) {
			d.Groups[0].Members[0].Fields.ProofBindingRefs = model.Own([]string{s})
		}},
		{"profile binding", func(d *model.Draft, s string) {
			d.Profiles[0].Fields.ProofBindingRefs = model.Own([]string{s})
			for index := range d.Groups[0].Members {
				d.Groups[0].Members[index].Fields.ProofBindingRefs = model.Field[[]string]{}
			}
		}},
		{"lifecycle evidence", func(d *model.Draft, s string) {
			d.Groups[2].Members[0].Fields.Lifecycle.Value.EvidenceRefs = []string{s}
		}},
		{"deferral evidence", func(d *model.Draft, s string) {
			d.Groups[1].Members[0].Fields.Deferral.Value.EvidenceRefs = []string{s}
		}},
	} {
		t.Run(role.name, func(t *testing.T) {
			for _, path := range []string{"proofkit/\xff.json", "proofkit/\u03bb.json"} {
				draft := testDraft()
				role.set(&draft, path)
				admitted, err := model.Normalize(draft)
				if strings.Contains(path, "\xff") {
					if model.ErrorCode(err) != "invalid_path" || strings.Contains(err.Error(), path) {
						t.Fatalf("malformed UTF-8 path was not rejected safely: code=%q", model.ErrorCode(err))
					}
					continue
				}
				if err != nil {
					t.Fatalf("valid Unicode path rejected: %v", err)
				}
				payload, err := Format(admitted)
				if err != nil {
					t.Fatal(err)
				}
				reparsed, err := Parse(payload)
				if err != nil || !projectionsEqual(admitted, reparsed.Model) {
					t.Fatalf("path round trip changed source identity: %v", err)
				}
			}
		})
	}
}
