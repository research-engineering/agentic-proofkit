package requirementcoverageview

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func admitCoverageRowMetadata(row map[string]any, rowsKey string, ownerSet map[string]struct{}, context string) error {
	switch rowsKey {
	case "requirementCoverage":
		requirementID, err := requirementsourceadmission.AdmitRequirementID(row["requirementId"], context+" requirementId")
		if err != nil {
			return err
		}
		if err := requireCanonicalWireString(row["requirementId"], requirementID, context+" requirementId"); err != nil {
			return err
		}
		claimLevel, err := requirementsourceadmission.AdmitClaimLevel(row["claimLevel"], context+" claimLevel")
		if err != nil {
			return err
		}
		if err := requireCanonicalWireString(row["claimLevel"], claimLevel, context+" claimLevel"); err != nil {
			return err
		}
		lifecycleState, err := requirementsourceadmission.AdmitLifecycleState(row["lifecycleState"], context+" lifecycleState")
		if err != nil {
			return err
		}
		if err := requireCanonicalWireString(row["lifecycleState"], lifecycleState, context+" lifecycleState"); err != nil {
			return err
		}
		invariant, err := requirementsourceadmission.AdmitInvariantText(row["invariant"], context+" invariant")
		if err != nil {
			return err
		}
		if err := requireCanonicalWireString(row["invariant"], invariant, context+" invariant"); err != nil {
			return err
		}
		if err := admitCoverageOwner(row["ownerId"], ownerSet, context+" ownerId"); err != nil {
			return err
		}
		if err := admitCoveragePath(row["specPath"], context+" specPath"); err != nil {
			return err
		}
		_, err = admit.PreserveSortedTextArray(row["nonClaims"], context+" nonClaims", true)
		return err
	case "ownerInvariantCoverage":
		if err := admitCoverageOwner(row["ownerId"], ownerSet, context+" ownerId"); err != nil {
			return err
		}
		if err := admitCoveragePath(row["sourcePath"], context+" sourcePath"); err != nil {
			return err
		}
		if err := admitCoverageText(row["summary"], context+" summary"); err != nil {
			return err
		}
		_, err := admit.PreserveSortedTextArray(row["nonClaims"], context+" nonClaims", true)
		return err
	case "commandCoverage":
		return nil
	default:
		return fmt.Errorf("%s has unsupported row kind", context)
	}
}

func admitCoverageOwner(raw any, ownerSet map[string]struct{}, context string) error {
	ownerID, err := admit.RuleID(raw, context)
	if err != nil {
		return err
	}
	if _, ok := ownerSet[ownerID]; !ok {
		return fmt.Errorf("%s must be within coverageBasis ownerIds", context)
	}
	return nil
}

func admitCoverageText(raw any, context string) error {
	value, ok := raw.(string)
	if !ok {
		return fmt.Errorf("%s must be text", context)
	}
	canonical, err := admit.NonEmptyText(value, context)
	if err != nil {
		return err
	}
	if canonical != value {
		return fmt.Errorf("%s must be canonical text", context)
	}
	return nil
}

func requireCanonicalWireString(raw any, canonical string, context string) error {
	value, ok := raw.(string)
	if !ok {
		return fmt.Errorf("%s must be text", context)
	}
	if value != canonical {
		return fmt.Errorf("%s must be canonical text", context)
	}
	return nil
}

func admitCoveragePath(raw any, context string) error {
	value, ok := raw.(string)
	if !ok {
		return fmt.Errorf("%s must be text", context)
	}
	canonical, err := admit.SafeRepoRelativePath(value, context)
	if err != nil {
		return err
	}
	if canonical != value {
		return fmt.Errorf("%s must be canonical", context)
	}
	return nil
}
