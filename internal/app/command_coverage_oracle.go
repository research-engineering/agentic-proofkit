package app

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

type CommandCoverageOracleCandidate struct {
	AssertionOracleID        string `json:"assertionOracleId"`
	CommandRef               string `json:"commandRef"`
	ExpectedPublicOutcome    string `json:"expectedPublicOutcome"`
	FalsificationEventID     string `json:"falsificationEventId"`
	NegativeCaseID           string `json:"negativeCaseId"`
	OracleKind               string `json:"oracleKind"`
	OwnerInvariantID         string `json:"ownerInvariantId"`
	PackagePath              string `json:"packagePath"`
	Selector                 string `json:"selector"`
	SourceMarker             string `json:"sourceMarker"`
	SourcePath               string `json:"sourcePath"`
	TestID                   string `json:"testId"`
	TestName                 string `json:"testName"`
	WrongImplementationClass string `json:"wrongImplementationClassId"`
}

func CommandCoverageOracleCandidates() ([]CommandCoverageOracleCandidate, error) {
	root, err := repositoryRootFromWorkingDirectory()
	if err != nil {
		return nil, err
	}
	return CommandCoverageOracleCandidatesAtRoot(root)
}

func CommandCoverageOracleCandidatesAtRoot(root string) ([]CommandCoverageOracleCandidate, error) {
	commands := make([]string, 0, len(commandCoverageRoutes))
	for command := range commandCoverageRoutes {
		commands = append(commands, command)
	}
	sort.Strings(commands)
	candidates := []CommandCoverageOracleCandidate{}
	seenTestIDs := map[string]struct{}{}
	seenMarkers := map[string]struct{}{}
	for _, command := range commands {
		for _, route := range commandCoverageRoutes[command] {
			if !route.isSemanticCandidate() {
				continue
			}
			if problem := route.semanticProofProblem(); problem != "" {
				return nil, fmt.Errorf("%s coverage route %s has invalid semantic proof metadata: %s", command, route.testName, problem)
			}
			if problem := routeSemanticOwnerProblem(command, route); problem != "" {
				return nil, fmt.Errorf("%s coverage route %s has invalid semantic owner scope: %s", command, route.testName, problem)
			}
			if problem := routeSemanticSourceProblemAtRoot(command, route, root); problem != "" {
				return nil, fmt.Errorf("%s coverage route %s has invalid source oracle: %s", command, route.testName, problem)
			}
			proof := route.semanticProof
			candidate := CommandCoverageOracleCandidate{
				AssertionOracleID:        proof.oracleID(),
				CommandRef:               CommandCoverageCommandRef(command),
				ExpectedPublicOutcome:    route.rationale,
				FalsificationEventID:     proof.falsifierID(),
				NegativeCaseID:           proof.negativeCaseID(),
				OracleKind:               "semantic_route_falsifier",
				OwnerInvariantID:         proof.semanticRouteInvariantID(),
				PackagePath:              "./" + filepath.ToSlash(filepath.Dir(route.file)),
				Selector:                 route.file + "::" + route.testName,
				SourceMarker:             route.sourceOracleMarker(command),
				SourcePath:               route.file,
				TestID:                   proof.routeTestID(),
				TestName:                 route.testName,
				WrongImplementationClass: proof.wrongImplementationClassID(),
			}
			if _, exists := seenTestIDs[candidate.TestID]; exists {
				return nil, fmt.Errorf("command coverage oracle candidate has duplicate test identity")
			}
			if _, exists := seenMarkers[candidate.SourceMarker]; exists {
				return nil, fmt.Errorf("command coverage oracle candidate has duplicate source marker")
			}
			seenTestIDs[candidate.TestID] = struct{}{}
			seenMarkers[candidate.SourceMarker] = struct{}{}
			candidates = append(candidates, candidate)
		}
	}
	sort.Slice(candidates, func(left, right int) bool {
		return strings.Join(candidateIdentity(candidates[left]), "\x00") < strings.Join(candidateIdentity(candidates[right]), "\x00")
	})
	return candidates, nil
}

func candidateIdentity(candidate CommandCoverageOracleCandidate) []string {
	return []string{
		candidate.CommandRef,
		candidate.Selector,
		candidate.TestID,
		candidate.OwnerInvariantID,
		candidate.FalsificationEventID,
		candidate.NegativeCaseID,
		candidate.WrongImplementationClass,
		candidate.AssertionOracleID,
		candidate.OracleKind,
		candidate.ExpectedPublicOutcome,
		candidate.SourceMarker,
		candidate.SourcePath,
		candidate.PackagePath,
		candidate.TestName,
	}
}
