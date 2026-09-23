package main

import (
	"fmt"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
)

func admitPackagedRequirementSource(entry, content string) (requirementsourceadmission.Source, error) {
	value, err := decodePackageJSONObject(content, "requirement source")
	if err != nil {
		return requirementsourceadmission.Source{}, err
	}
	result, err := requirementsourceadmission.Evaluate(value)
	if err != nil || result.ExitCode != 0 {
		return requirementsourceadmission.Source{}, fmt.Errorf("packaged requirement source must pass source admission")
	}
	if entry != "package/"+result.Source.RequirementsPath() {
		return requirementsourceadmission.Source{}, fmt.Errorf("packaged requirement source path differs from its admitted identity")
	}
	return result.Source, nil
}

func verifyRequirementSourceReferences(entry, content string, entries map[string]struct{}) error {
	source, err := admitPackagedRequirementSource(entry, content)
	if err != nil {
		return err
	}
	value, err := requirementsourceadmission.SourceValue(source)
	if err != nil {
		return err
	}
	classifications := map[string]string{
		"/specPackagePath":               "package_public_directory",
		"/sourceNonClaimRefs":            "source_local_nonclaim_identifier",
		"/derivations/*/sourceRef":       "commit_bound_source_declaration",
		"/derivations/*/sourceRef/path":  "commit_bound_source_path",
		"/derivations/*/selector":        "commit_bound_byte_range",
		"/derivations/*/nonClaimRefs":    "source_local_nonclaim_identifier",
		"/scenarios/*/vocabularyRefs":    "source_local_vocabulary_identifier",
		"/scenarios/*/nonClaimRefs":      "source_local_nonclaim_identifier",
		"/scenarios/*/examples/*/values": "literal_string_map",
	}
	for _, prefix := range []string{"/profiles/*/fields", "/groups/*/members/*/fields"} {
		for field, class := range map[string]string{
			"/proofBindingRefs": "package_public", "/nonClaimRefs": "source_local_nonclaim_identifier",
			"/externalNonClaimRefs": "external_nonclaim_identifier", "/lifecycle/evidenceRefs": "package_public_or_evidence_identifier",
			"/deferral/expiryRef": "rule_identifier", "/deferral/evidenceRefs": "package_public_or_evidence_identifier",
		} {
			classifications[prefix+field] = class
		}
	}
	if err := verifyClosedReferenceInventory("requirement source", value, classifications); err != nil {
		return err
	}
	if err := requireShippedRootPrefix("requirement source specPackagePath", source.SpecPackagePath(), entries); err != nil {
		return err
	}
	for _, reference := range []string{source.OverviewPath(), source.RequirementsPath()} {
		if err := requireShippedRootReference("requirement source derived path", reference, entries); err != nil {
			return err
		}
	}
	for _, requirement := range source.Requirements() {
		for _, reference := range requirement.ProofBindingRefs {
			if err := requireShippedRootReference("requirement source proofBindingRef", reference, entries); err != nil {
				return err
			}
		}
		for _, reference := range requirement.ExternalNonClaimRefs {
			if !strings.HasPrefix(reference, "NC-") {
				return fmt.Errorf("packaged external nonclaim reference must be an NC-* identifier")
			}
		}
		evidence := append([]string{}, requirement.Lifecycle.EvidenceRefs...)
		if requirement.Deferral != nil {
			evidence = append(evidence, requirement.Deferral.EvidenceRefs...)
		}
		for _, reference := range evidence {
			if looksLikeRepositoryPath(reference) {
				if err := requireShippedRootReference("requirement source evidenceRef", reference, entries); err != nil {
					return err
				}
			}
		}
	}
	// Source-local links and commit-bound lexical identities are already admitted
	// by the source owner. Historical Git paths need not exist in this checkout.
	return nil
}
