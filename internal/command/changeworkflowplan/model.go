package changeworkflowplan

const (
	reportKind              = "proofkit.change-workflow-plan"
	maxCandidateContextRefs = 48
	maxCandidatePathBytes   = 18_432
	maxDependenciesPerRef   = 8
	maxFindings             = 12
	maxJSONBytes            = 128 << 10
	maxPathBytes            = 384
	maxRequiredContextRefs  = 12
	maxRetainedContextRefs  = 24
	maxRetainedPathBytes    = 9_216
	maxTextBytes            = 8_192
	maxTextLines            = 24
	missingAuthorityTarget  = "missing_consuming_repository_semantic_owner"
	missingConsumerWitness  = "missing_consumer_witness"
)

var boundaryNonClaims = []string{
	"Change workflow plans do not authenticate caller assertions, context, digests, checkpoint state, or external state.",
	"Change workflow plans do not approve repository edits, merge, release, rollout, or production readiness.",
	"Change workflow plans do not execute or supervise agents, native witnesses, repository operations, providers, or CI.",
	"Change workflow prompts, reports, text, and envelopes are derived projections and are not semantic authority.",
	"The reviewed-change workflow is an optional built-in profile and is not a universal consuming-repository process policy.",
}

type contextRef struct {
	ArtifactPath     string
	DependencyRefIDs []string
	RefID            string
	RefKind          string
	SubjectDigest    string
}

type checkpoint struct {
	AssessmentSubjectDigest string
	FindingRefs             []string
	State                   string
	SubjectDigest           string
	SubjectRefID            string
}

type admittedInput struct {
	Checkpoint              *checkpoint
	CompletedStageIDs       []string
	ContextRefs             []contextRef
	GoverningAuthorityRefID *string
	RequiredContextRefIDs   []string
	SchemaVersion           int
}

type stateDecision struct {
	Action              string
	ActiveStageID       string
	CheckpointState     string
	OutputKind          string
	SuccessorStateDelta *successorStateDelta
}

type stateRow struct {
	Action          string
	ActiveStageID   string
	CheckpointState string
	CompletedCount  int
	OutputKind      string
	Terminal        bool
}

type successorStateDelta struct {
	Checkpoint        *checkpoint
	CompletedStageIDs []string
}

type closureResult struct {
	Omitted  []contextRef
	Retained []contextRef
}

type projection struct {
	Decision stateDecision
	Input    admittedInput
	Closure  closureResult
	Prompt   map[string]any
	Plan     map[string]any
}

// TextLine separates command-owned labels from admitted values so a caller may
// style labels without parsing or altering semantic text values.
type TextLine struct {
	Label string
	Value string
}

// Result is the complete set of deterministic presentation projections for
// one admitted snapshot. Callers select one projection; none is authoritative.
type Result struct {
	AgentEnvelope map[string]any
	Plan          map[string]any
	Text          string
	TextLines     []TextLine
}
