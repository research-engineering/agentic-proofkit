package adoptionmaterialization

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathidentity"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

type pathRole string

const (
	roleBindingTarget          pathRole = "binding_target"
	roleInventoryTarget        pathRole = "inventory_target"
	roleManifestTarget         pathRole = "manifest_target"
	roleOverviewReference      pathRole = "overview_reference"
	roleRequirementSource      pathRole = "requirement_source_target"
	roleRequirementSpecRef     pathRole = "requirement_spec_reference"
	roleTestSourceReference    pathRole = "test_source_reference"
	roleWitnessSourceReference pathRole = "witness_source_reference"
)

type pathUse struct {
	Path   string
	Role   pathRole
	Target bool
}

func validatePathRoles(uses []pathUse) error {
	for index, use := range uses {
		if _, err := pathidentity.Key(use.Path); err != nil {
			return fmt.Errorf("adoption materialization %s path identity is invalid", use.Role)
		}
		overlapsControl, err := pathidentity.Overlaps(use.Path, repositorytransaction.ControlRoot)
		if err != nil || overlapsControl {
			return fmt.Errorf("adoption materialization %s path overlaps the transaction control namespace", use.Role)
		}
		for prior := 0; prior < index; prior++ {
			overlaps, err := pathidentity.Overlaps(use.Path, uses[prior].Path)
			if err != nil {
				return fmt.Errorf("adoption materialization path identity is invalid")
			}
			if overlaps && !compatiblePathUses(use, uses[prior]) {
				return fmt.Errorf("adoption materialization path roles conflict: %s and %s", uses[prior].Role, use.Role)
			}
		}
	}
	return nil
}

func compatiblePathUses(left, right pathUse) bool {
	if !left.Target && !right.Target {
		return true
	}
	if left.Target && right.Target {
		return false
	}
	target, reference := left, right
	if !target.Target {
		target, reference = right, left
	}
	if target.Role != roleRequirementSource || reference.Role != roleRequirementSpecRef {
		return false
	}
	leftKey, leftErr := pathidentity.Key(target.Path)
	rightKey, rightErr := pathidentity.Key(reference.Path)
	return leftErr == nil && rightErr == nil && leftKey == rightKey
}
