package requirementsourcemodel

// Field represents one lexical owner of an effective metadata value. Present
// distinguishes an omitted field from a present zero or nullable value.
type Field[T any] struct {
	Present bool
	Value   T
}

func Own[T any](value T) Field[T] {
	return Field[T]{Present: true, Value: value}
}

type ClaimLevel string

const (
	ClaimAdvisory ClaimLevel = "advisory"
	ClaimBlocking ClaimLevel = "blocking"
	ClaimDeferred ClaimLevel = "deferred"
)

type RiskClass string

const (
	RiskCritical RiskClass = "critical"
	RiskHigh     RiskClass = "high"
	RiskLow      RiskClass = "low"
	RiskMedium   RiskClass = "medium"
)

type LifecycleState string

const (
	LifecycleActive     LifecycleState = "active"
	LifecycleDeprecated LifecycleState = "deprecated"
	LifecycleRemoved    LifecycleState = "removed"
	LifecycleSuperseded LifecycleState = "superseded"
)

type TermKind string

const (
	TermAction     TermKind = "action"
	TermObservable TermKind = "observable"
	TermState      TermKind = "state"
	TermSubject    TermKind = "subject"
	TermValue      TermKind = "value"
)

type SourceKind string

const (
	SourceClarification SourceKind = "clarification"
	SourceCodeSnapshot  SourceKind = "code_snapshot"
	SourceDesign        SourceKind = "design"
	SourceOwnerDecision SourceKind = "owner_decision"
	SourcePlan          SourceKind = "plan"
)

type ObjectFormat string

const (
	ObjectSHA1   ObjectFormat = "sha1"
	ObjectSHA256 ObjectFormat = "sha256"
)

type ScenarioValue string

type MetadataFieldID string

type MetadataOwnerKind string

const (
	MetadataOwnerMember  MetadataOwnerKind = "member"
	MetadataOwnerProfile MetadataOwnerKind = "profile"
)

type EntityKind string

const (
	EntityDerivation  EntityKind = "derivation"
	EntityGroup       EntityKind = "group"
	EntityNonClaim    EntityKind = "nonclaim"
	EntityProfile     EntityKind = "profile"
	EntityRequirement EntityKind = "requirement"
	EntityScenario    EntityKind = "scenario"
	EntitySource      EntityKind = "source"
	EntityTerm        EntityKind = "term"
)

type ReferenceKind string

const (
	ReferenceDerivationNonClaim    ReferenceKind = "derivation_nonclaim"
	ReferenceDerivationRequirement ReferenceKind = "derivation_requirement"
	ReferenceGroupMember           ReferenceKind = "group_member"
	ReferenceGroupProfile          ReferenceKind = "group_profile"
	ReferenceLifecycleReplacement  ReferenceKind = "lifecycle_replacement"
	ReferenceRequirementNonClaim   ReferenceKind = "requirement_nonclaim"
	ReferenceScenarioNonClaim      ReferenceKind = "scenario_nonclaim"
	ReferenceScenarioRequirement   ReferenceKind = "scenario_requirement"
	ReferenceScenarioVocabulary    ReferenceKind = "scenario_vocabulary"
	ReferenceSourceNonClaim        ReferenceKind = "source_nonclaim"
)

type Draft struct {
	SourceID            string
	SpecPackagePath     string
	SourceNonClaimRefs  []string
	NonClaimDefinitions []NonClaimDefinition
	Vocabulary          []VocabularyTerm
	Derivations         []Derivation
	Profiles            []Profile
	Groups              []Group
	Scenarios           []Scenario
}

type NonClaimDefinition struct {
	NonClaimID string
	Statement  string
}

type VocabularyTerm struct {
	TermID     string
	Kind       TermKind
	Label      string
	Definition string
}

type Derivation struct {
	DerivationID   string
	SourceKind     SourceKind
	SourceRef      GitBlobRef
	Selector       ByteRange
	RequirementIDs []string
	NonClaimRefs   []string
}

type GitBlobRef struct {
	ObjectFormat ObjectFormat
	CommitOID    string
	Path         string
	SHA256       string
}

type ByteRange struct {
	Start int64
	End   int64
}

type Profile struct {
	ProfileID string
	Fields    MetadataFields
}

type Group struct {
	GroupID        string
	ProfileID      string
	StatementStem  string
	SharedPremises []string
	Members        []Member
}

type Member struct {
	RequirementID       string
	StatementCompletion string
	Fields              MetadataFields
}

type MetadataFields struct {
	OwnerID      Field[string]
	ClaimLevel   Field[ClaimLevel]
	RiskClass    Field[RiskClass]
	NonClaimRefs Field[[]string]
	Lifecycle    Field[Lifecycle]
	Deferral     Field[*Deferral]
	UpdatePolicy Field[UpdatePolicy]
}

type Lifecycle struct {
	State                     LifecycleState
	ReplacementRequirementIDs []string
	EvidenceRefs              []string
}

type Deferral struct {
	OwnerID         string
	RiskAcceptedBy  string
	ReviewCondition string
	ExpiryRef       string
	MergePolicy     string
	EvidenceRefs    []string
}

type UpdatePolicy struct {
	ReviewOwnerID              string
	RequiresImpactDeclaration  bool
	RequiresProofBindingReview bool
}

type Scenario struct {
	ScenarioID            string
	RequirementIDs        []string
	Parameters            []string
	Preconditions         []string
	ActionSequence        []string
	ExpectedObservations  []string
	ForbiddenObservations []string
	Examples              []Example
	VocabularyRefs        []string
	NonClaimRefs          []string
}

type Example struct {
	ExampleID string
	Values    map[string]ScenarioValue
}

// Model owns the admitted normalized value. Its fields remain private so a
// caller cannot mutate the owner snapshot through a returned slice or map.
type Model struct {
	atomic     AtomicProjection
	layout     LayoutProjection
	references ReferenceProjection
}

type AtomicProjection struct {
	SourceID            string
	SpecPackagePath     string
	SourceNonClaimRefs  []string
	NonClaimDefinitions []NonClaimDefinition
	Vocabulary          []VocabularyTerm
	Requirements        []AtomicRequirement
	Scenarios           []Scenario
}

type AtomicRequirement struct {
	RequirementID  string
	Invariant      string
	SharedPremises []string
	OwnerID        string
	ClaimLevel     ClaimLevel
	RiskClass      RiskClass
	NonClaimRefs   []string
	Lifecycle      Lifecycle
	Deferral       *Deferral
	UpdatePolicy   UpdatePolicy
}

type LayoutProjection struct {
	SourceID string
	Profiles []Profile
	Groups   []Group
	Origins  []Origin
}

type Origin struct {
	RequirementID string
	GroupID       string
	ProfileID     string
	FieldOwners   []FieldOwner
}

type FieldOwner struct {
	FieldID   MetadataFieldID
	OwnerKind MetadataOwnerKind
	OwnerID   string
}

type ReferenceProjection struct {
	SourceID    string
	Derivations []Derivation
	Edges       []ReferenceEdge
}

type ReferenceEdge struct {
	Kind ReferenceKind
	From ReferenceEndpoint
	To   ReferenceEndpoint
}

type ReferenceEndpoint struct {
	Kind EntityKind
	ID   string
}

func (model Model) Atomic() AtomicProjection {
	return cloneAtomicProjection(model.atomic)
}

func (model Model) Layout() LayoutProjection {
	return cloneLayoutProjection(model.layout)
}

func (model Model) References() ReferenceProjection {
	return cloneReferenceProjection(model.references)
}
