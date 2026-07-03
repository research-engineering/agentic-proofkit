package requirementcoverageview

import (
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
)

var defaultNonClaims = []string{
	"Requirement coverage views are rendered lookup products only.",
	"Requirement coverage views do not scan repositories, execute native tests, authenticate receipts, decide proof freshness, or approve merge.",
	"Requirement coverage views classify only caller-owned structured inputs.",
	"Route-only smoke evidence cannot satisfy semantic requirement coverage.",
}

type Options struct {
	AgentEnvelope bool
}
type compositeInput struct {
	CoverageUniverse       coverageUniverse
	Inventory              *testevidenceinventory.Result
	LocalEnvironmentPolicy *localEnvironmentPolicy
	OwnerInvariantRegistry ownerInvariantRegistry
	Proof                  proofProjection
	Source                 requirementsourceadmission.Source
	ViewInputID            string
}
type coverageUniverse struct {
	Authority               string
	CodeSurfaces            []surface
	CommandRefs             []string
	CompletenessDeclaration string
	NonClaims               []string
	OwnerIDs                []string
	SpecSurfaces            []surface
	TestSurfaces            []surface
	UniverseID              string
}
type surface struct {
	OwnerID   string
	Path      string
	SurfaceID string
}
type ownerInvariantRegistry struct {
	Invariants []ownerInvariant
	NonClaims  []string
	RegistryID string
}
type ownerInvariant struct {
	NonClaims        []string
	OwnerID          string
	OwnerInvariantID string
	SourcePath       string
	Summary          string
}
type localEnvironmentPolicy struct {
	Authority               string
	LocalEnvironmentClasses []string
}
type proofProjection struct {
	BindingID        string
	CommandIDs       []string
	ContractID       string
	Mode             string
	Requirements     map[string]proofRequirement
	WitnessRefs      []string
	WitnessSelectors []string
}
type proofRequirement struct {
	CommandIDs         []string
	EnvironmentClasses []string
	ProofState         string
	Scenarios          []scenario
	VerifyCommands     []string
	WitnessRefs        []string
	WitnessSelectors   []string
}
type scenario struct {
	CommandIDs         []string
	EnvironmentClasses []string
	ScenarioID         string
	WitnessID          string
	WitnessKind        string
	WitnessPath        string
}
