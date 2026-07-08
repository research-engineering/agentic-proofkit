package selectivegateplan

import "github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"

var edgeClassSet = proofvocab.SelectiveEdgeClassSet()

type command struct {
	Command          string
	CommandOwnership *string
	ID               string
	Reason           string
	SourcePath       *string
}

type scanObligation struct {
	Command          string
	CommandID        string
	CommandOwnership string
	Mode             string
	Reason           string
	Required         bool
}

type generatedArtifactRule struct {
	Command              string
	Generator            string
	Path                 string
	SourceOfTruthPattern []string
}

type generatedArtifactObligation struct {
	Generator     string
	Path          string
	Reason        string
	SourceOfTruth []string
}

type artifactIntegrityPolicy struct {
	Command     string
	PathPattern string
	Policy      string
}

type artifactIntegrityObligation struct {
	Command string
	Path    string
	Policy  string
}

type witnessObligation struct {
	Commands       []string
	Path           string
	RequirementIDs []string
}

type fallbackCoverage struct {
	Command     command
	EdgeClasses []string
	Reason      string
}

type unknownEdge struct {
	EdgeClass string
	EdgeID    string
	Path      string
	Reason    string
}

type unknownEdgeAssessment struct {
	unknownEdge
	CoverageState      string
	FallbackCommandIDs []string
}

type skippedGate struct {
	ID     string
	Reason string
}

type pathTriggeredCommand struct {
	Command      command
	PathPatterns []string
}

type commandAccumulator struct {
	byKey map[string]command
	order []string
}

type input struct {
	ArchiveOrBinaryPathPatterns []string
	ArtifactIntegrityPolicies   []artifactIntegrityPolicy
	BaseCommands                []command
	ChangedPaths                []string
	DependencyCommand           string
	DependencyPaths             []string
	FallbackCoverage            []fallbackCoverage
	FullWorkspaceCommand        *command
	GeneratedArtifactRules      []generatedArtifactRule
	IgnoredProofLikePaths       []string
	NonClaims                   []string
	PackageCommands             []command
	PathTriggeredCommands       []pathTriggeredCommand
	PreexistingFailures         []string
	PrivatePathPrefixes         []string
	ProofLikePathPatterns       []string
	PublicAPICommand            string
	PublicAPITouched            bool
	RequirementImpactCommand    string
	RequirementImpactTouched    bool
	ScanObligation              scanObligation
	TouchedRequirementWitnesses []witnessObligation
	UnknownEdges                []unknownEdge
}
