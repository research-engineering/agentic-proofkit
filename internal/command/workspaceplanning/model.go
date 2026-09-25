package workspaceplanning

import "github.com/research-engineering/agentic-proofkit/internal/kernel/pathpattern"

type dependencyNode struct {
	Name                  string
	WorkspaceDependencies []string
}

type packagePathNode struct {
	DirName string
	dependencyNode
}

type escalationRule struct {
	Pattern pathpattern.Pattern
	Reason  string
}

type changedPlanInput struct {
	ChangedPaths             []string
	EscalationRules          []escalationRule
	IncludeReverseDependents bool
	Packages                 []packagePathNode
	PackagesRoot             string
}

type shardInput struct {
	Packages   []dependencyNode
	Roots      []dependencyNode
	ShardTotal int
}
