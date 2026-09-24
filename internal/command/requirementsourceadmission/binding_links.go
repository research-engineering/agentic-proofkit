package requirementsourceadmission

import "fmt"

type BindingRequirementLink struct {
	RequirementID string
	OwnerID       string
	ClaimLevel    string
	SpecPath      string
}

// AdmitBindingRequirementLinks checks only fields owned by the admitted
// requirement source. Binding-specific proof state and non-claims remain with
// the binding owner.
func AdmitBindingRequirementLinks(sources []Source, links []BindingRequirementLink) error {
	type target struct {
		requirement Requirement
		path        string
	}
	byID := map[string]target{}
	for _, source := range sources {
		if !source.admitted {
			return fmt.Errorf("binding links require admitted requirement sources")
		}
		for _, requirement := range source.Requirements() {
			if _, duplicate := byID[requirement.RequirementID]; duplicate {
				return fmt.Errorf("binding links require unique requirement ownership")
			}
			byID[requirement.RequirementID] = target{requirement: requirement, path: source.RequirementsPath()}
		}
	}
	for _, link := range links {
		source, exists := byID[link.RequirementID]
		if !exists {
			return fmt.Errorf("binding link references a requirement outside admitted sources")
		}
		if link.OwnerID != source.requirement.OwnerID || link.ClaimLevel != source.requirement.ClaimLevel || link.SpecPath != source.path {
			return fmt.Errorf("binding link disagrees with source-owned requirement fields")
		}
	}
	return nil
}
