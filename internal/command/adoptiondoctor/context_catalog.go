package adoptiondoctor

import "fmt"

const (
	contextRoleSpecPath        = "spec_path"
	contextRoleProofBinding    = "proof_binding"
	contextRoleNativeWitness   = "native_witness"
	contextRoleAffectedPath    = "affected_path"
	contextRoleContractWitness = "contract_witness"
	contextRoleAuthorityPath   = "authority_path"
	contextRoleEvidence        = "evidence"
)

type contextCatalog struct {
	doctorID string
	refs     []map[string]any
	byOrigin map[inputRecordOrigin][]string
}

func newContextCatalog(input Input) contextCatalog {
	catalog := contextCatalog{doctorID: input.DoctorID, refs: []map[string]any{}, byOrigin: map[inputRecordOrigin][]string{}}
	for _, route := range input.OwnerRoutes {
		origin := inputRecordOrigin{recordKindOwnerRoute, route.RouteID}
		catalog.add(origin, route.Owner, contextRoleSpecPath, route.SpecPaths)
		catalog.add(origin, route.Owner, contextRoleProofBinding, route.ProofBindingPaths)
		catalog.add(origin, route.Owner, contextRoleNativeWitness, route.NativeWitnessRefs)
	}
	for _, candidate := range input.CandidateBoundaries {
		origin := inputRecordOrigin{recordKindCandidateBoundary, candidate.BoundaryID}
		catalog.add(origin, candidate.CandidateOwner, contextRoleAffectedPath, candidate.AffectedPaths)
		catalog.add(origin, candidate.CandidateOwner, contextRoleContractWitness, candidate.ContractWitnessRefs)
		catalog.add(origin, candidate.CandidateOwner, contextRoleNativeWitness, candidate.NativeWitnessRefs)
		catalog.add(origin, candidate.CandidateOwner, contextRoleProofBinding, candidate.ProofBindingRefs)
	}
	for _, surface := range input.StaleAuthority.AuthoritySurfaces {
		origin := inputRecordOrigin{recordKindStaleAuthoritySurface, surface.SurfaceID}
		catalog.add(origin, surface.Owner, contextRoleAuthorityPath, []string{surface.Path})
		catalog.add(origin, surface.Owner, contextRoleEvidence, surface.EvidenceRefs)
	}
	for _, child := range input.ChildReports {
		catalog.add(inputRecordOrigin{recordKindChildReport, child.ReportID}, consumerRepositoryOwner, contextRoleEvidence, child.EvidenceRefs)
	}
	for _, blocked := range input.BlockedPreconditions {
		catalog.add(inputRecordOrigin{recordKindBlockedPrecondition, blocked.PreconditionID}, blocked.Owner, contextRoleEvidence, blocked.EvidenceRefs)
	}
	return catalog
}

func (catalog *contextCatalog) add(origin inputRecordOrigin, owner, role string, paths []string) {
	for _, path := range paths {
		id := fmt.Sprintf("%s.%s.context.%03d", origin.kind, origin.id, len(catalog.byOrigin[origin])+1)
		id = catalog.localTargetID(id)
		catalog.refs = append(catalog.refs, map[string]any{
			"kind": origin.kind, "role": role, "sourceId": origin.id,
			"nonClaim": "Context refs are caller-owned selectors only; they do not prove freshness, semantic correctness, or execution authority.",
			"owner":    owner, "path": path, "refId": id,
		})
		catalog.byOrigin[origin] = append(catalog.byOrigin[origin], id)
	}
}

func (catalog contextCatalog) localTargetID(id string) string {
	if id == catalog.doctorID {
		// All ordinary local target IDs end in a numeric ordinal.
		return id + ".local"
	}
	return id
}

func (catalog contextCatalog) evidenceForGap(item gap) []string {
	if item.origin.kind == recordKindDoctor {
		// These are generated doctor IDs, never caller path or descriptive text.
		return []string{item.origin.id}
	}
	return catalog.byOrigin[item.origin]
}
