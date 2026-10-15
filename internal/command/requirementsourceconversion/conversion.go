// Package requirementsourceconversion converts one requirement source between
// the grouped authoring document and a flat interchange document through the
// single admitted requirementsourcemodel.Model.
package requirementsourceconversion

import (
	"reflect"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

const (
	TargetFlat    = "flat"
	TargetGrouped = "grouped"

	legacySchemaVersion = 1
)

// TargetChoices is the closed --to vocabulary in sorted order.
func TargetChoices() []string { return []string{TargetFlat, TargetGrouped} }

type sourceFormat uint8

const (
	formatGrouped sourceFormat = iota + 1
	formatFlat
)

// ExportFlat admits a grouped source and emits its complete flat document.
// The conversion is total on admitted models: no field is dropped and no loss
// acceptance exists because the flat document holds every ownership coordinate.
func ExportFlat(input any) (map[string]any, error) {
	format, err := detectFormat(input, documentInput)
	if err != nil {
		return nil, err
	}
	if format != formatGrouped {
		return nil, refusal(documentInput, "same_format", "/kind")
	}
	model, err := readGrouped(input, documentInput)
	if err != nil {
		return nil, err
	}
	flat, err := writeFlat(model)
	if err != nil {
		return nil, err
	}
	reread, err := readFlat(flat)
	if err != nil || !sameModel(model, reread.model) {
		return nil, refusal(documentInput, "emission_readback_mismatch", "")
	}
	return flat, nil
}

// ImportFlat reconstructs a grouped source from a flat document and the grouped
// baseline named by its basisDigest. Values may differ from the baseline;
// identity and ownership coordinates may not.
func ImportFlat(input any, baseline any) (map[string]any, error) {
	format, err := detectFormat(input, documentInput)
	if err != nil {
		return nil, err
	}
	if format != formatFlat {
		return nil, refusal(documentInput, "same_format", "/kind")
	}
	reconstruction, err := readFlat(input)
	if err != nil {
		return nil, err
	}
	baselineFormat, err := detectFormat(baseline, documentBaseline)
	if err != nil {
		return nil, err
	}
	if baselineFormat != formatGrouped {
		return nil, refusal(documentBaseline, "baseline_not_grouped_source", "/kind")
	}
	baselineModel, err := readGrouped(baseline, documentBaseline)
	if err != nil {
		return nil, err
	}
	baselineDigest, err := modelDigest(baselineModel)
	if err != nil {
		return nil, refusal(documentBaseline, "source_admission_failed", "")
	}
	if baselineDigest != reconstruction.basisDigest {
		return nil, refusal(documentInput, "stale_baseline", "/basisDigest")
	}
	if err := compareOwnership(reconstruction, baselineModel); err != nil {
		return nil, err
	}
	grouped, err := requirementsourcecodec.Value(reconstruction.model)
	if err != nil {
		return nil, refusal(documentInput, "emission_readback_mismatch", "")
	}
	reread, err := readGrouped(grouped, documentInput)
	if err != nil || !sameModel(reconstruction.model, reread) {
		return nil, refusal(documentInput, "emission_readback_mismatch", "")
	}
	return grouped, nil
}

// detectFormat binds a document to its admitted identity; filenames, flags and
// field shapes never select a format.
func detectFormat(raw any, document string) (sourceFormat, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return 0, refusal(document, "unsupported_source_format", "")
	}
	kind, hasKind := record["kind"]
	version := record["schemaVersion"]
	switch {
	case hasKind && kind == requirementsourcecodec.DocumentKind && admit.JSONNumberEquals(version, requirementsourcecodec.SchemaVersion):
		return formatGrouped, nil
	case hasKind && kind == FlatDocumentKind && admit.JSONNumberEquals(version, FlatSchemaVersion):
		return formatFlat, nil
	case !hasKind && admit.JSONNumberEquals(version, legacySchemaVersion):
		return 0, refusal(document, "legacy_source_unsupported", "/schemaVersion")
	}
	return 0, refusal(document, "unsupported_source_format", "")
}

func readGrouped(raw any, document string) (requirementsourcemodel.Model, error) {
	identity := func(path string) string { return path }
	return admitGroupedValue(raw, document, identity, groupedMemberLocator(raw))
}

// groupedMemberLocator resolves a policy-failing requirement to its member in
// the caller's grouped document. Only admitted canonical IDs are compared.
func groupedMemberLocator(raw any) func(string) string {
	return func(requirementID string) string {
		record, _ := raw.(map[string]any)
		groups, _ := record["groups"].([]any)
		for groupIndex, group := range groups {
			groupRecord, _ := group.(map[string]any)
			members, _ := groupRecord["members"].([]any)
			for memberIndex, member := range members {
				memberRecord, _ := member.(map[string]any)
				if memberRecord["requirementId"] == requirementID {
					return pointer("groups", groupIndex, "members", memberIndex)
				}
			}
		}
		return "/groups"
	}
}

// modelDigest identifies the admitted model by its canonical grouped bytes, so
// reformatting a baseline does not make it stale and every read path agrees.
func modelDigest(model requirementsourcemodel.Model) (string, error) {
	canonical, err := requirementsourcecodec.Format(model)
	if err != nil {
		return "", err
	}
	return digest.SHA256BytesRef(canonical), nil
}

// sameModel is full authoring equality: resolved values, layout ownership and
// references. It is stronger than resolved-value equality alone.
func sameModel(left, right requirementsourcemodel.Model) bool {
	return reflect.DeepEqual(left.Atomic(), right.Atomic()) &&
		reflect.DeepEqual(left.Layout(), right.Layout()) &&
		reflect.DeepEqual(left.References(), right.References())
}
