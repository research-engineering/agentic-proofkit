package main

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
)

func buildCommandRouteMetrics(contract cliContract, summaries []app.CommandCoverageSummary, inventory testevidenceinventory.Inventory) commandRouteMetrics {
	return buildCommandRouteMetricsWithExecution(contract, summaries, inventory, commandExecutionSummary{})
}

func buildCommandRouteMetricsWithExecution(contract cliContract, summaries []app.CommandCoverageSummary, inventory testevidenceinventory.Inventory, execution commandExecutionSummary) commandRouteMetrics {
	missingCandidates := []string{}
	missingDeclaredSemanticRoutes := []string{}
	missingExecutionBackedSemanticRoutes := []string{}
	contractRefs := map[string]string{}
	knownRefs := map[string]struct{}{}
	candidateRefs := map[string]struct{}{}
	declaredSemanticRouteRefs := map[string]struct{}{}
	executionBackedSemanticRouteRefs := map[string]struct{}{}
	routeOnlyCount := 0
	candidateEntryCount := 0
	declaredSemanticRouteEntryCount := 0
	for _, command := range contract.Commands {
		contractRefs[app.CommandCoverageCommandRef(command.Command)] = command.Command
	}
	for _, summary := range summaries {
		knownRefs[summary.CommandRef] = struct{}{}
	}
	for _, commandRef := range execution.CommandRefs {
		executionBackedSemanticRouteRefs[commandRef] = struct{}{}
	}
	for _, entry := range inventory.Entries {
		switch entry.EvidenceClass {
		case testevidenceinventory.EvidenceClassDeclaredSemanticFalsifierRoute:
			declaredSemanticRouteEntryCount++
			for _, commandRef := range entry.CommandRefs {
				declaredSemanticRouteRefs[commandRef] = struct{}{}
			}
		case testevidenceinventory.EvidenceClassProofRouteCandidate:
			candidateEntryCount++
			for _, commandRef := range entry.CommandRefs {
				candidateRefs[commandRef] = struct{}{}
			}
		case "routing_smoke_nonclaim":
			routeOnlyCount++
		}
	}
	unknownDeclaredSemanticRouteRefs := unknownCommandRefs(declaredSemanticRouteRefs, knownRefs)
	unknownCandidateRefs := unknownCommandRefs(candidateRefs, knownRefs)
	unknownExecutionBackedSemanticRouteRefs := unknownCommandRefs(executionBackedSemanticRouteRefs, knownRefs)
	contractOnly := []string{}
	for ref, command := range contractRefs {
		if _, ok := knownRefs[ref]; !ok {
			contractOnly = append(contractOnly, command)
		}
	}
	routeOnly := []string{}
	for _, summary := range summaries {
		if _, ok := contractRefs[summary.CommandRef]; !ok {
			routeOnly = append(routeOnly, summary.Command)
		}
	}
	sort.Strings(contractOnly)
	sort.Strings(routeOnly)
	out := commandRouteMetrics{
		AdmittedInventoryEntryCount:                        len(inventory.Entries),
		CommandCount:                                       len(summaries),
		ContractOnlyCommands:                               contractOnly,
		ContractOnlyCommandCount:                           len(contractOnly),
		RouteOnlyCommands:                                  routeOnly,
		RouteOnlyCommandCount:                              len(routeOnly),
		RouteSmokeCount:                                    routeOnlyCount,
		ProofRouteCandidateInventoryEntryCount:             candidateEntryCount,
		DeclaredSemanticFalsifierRouteEntryCount:           declaredSemanticRouteEntryCount,
		UnknownProofRouteCandidateRefs:                     unknownCandidateRefs,
		UnknownProofRouteCandidateRefCount:                 len(unknownCandidateRefs),
		UnknownDeclaredSemanticRouteCommandRefs:            unknownDeclaredSemanticRouteRefs,
		UnknownDeclaredSemanticRouteCommandRefCount:        len(unknownDeclaredSemanticRouteRefs),
		CommandOracleCandidateSetDigest:                    execution.CandidateSetDigest,
		CommandOracleCounterfeitCorpusDigest:               execution.CounterfeitCorpusDigest,
		CommandOracleRecordDigest:                          execution.RecordDigest,
		CommandOracleSourceSnapshotDigest:                  execution.SourceSnapshotDigest,
		ExecutionBackedSemanticRouteEntryCount:             execution.CandidateCount,
		UnknownExecutionBackedSemanticRouteCommandRefs:     unknownExecutionBackedSemanticRouteRefs,
		UnknownExecutionBackedSemanticRouteCommandRefCount: len(unknownExecutionBackedSemanticRouteRefs),
	}
	for _, summary := range summaries {
		out.Commands = append(out.Commands, summary.Command)
		out.RouteCount += summary.RouteCount
		out.ProofRouteCandidateRouteCount += summary.ProofRouteCandidateCount
		if _, ok := candidateRefs[summary.CommandRef]; !ok {
			missingCandidates = append(missingCandidates, summary.Command)
		}
		if _, ok := declaredSemanticRouteRefs[summary.CommandRef]; !ok {
			missingDeclaredSemanticRoutes = append(missingDeclaredSemanticRoutes, summary.Command)
		}
		if _, ok := executionBackedSemanticRouteRefs[summary.CommandRef]; !ok {
			missingExecutionBackedSemanticRoutes = append(missingExecutionBackedSemanticRoutes, summary.Command)
		}
	}
	sort.Strings(out.Commands)
	sort.Strings(missingCandidates)
	sort.Strings(missingDeclaredSemanticRoutes)
	sort.Strings(missingExecutionBackedSemanticRoutes)
	out.CommandsWithoutProofRouteCandidate = missingCandidates
	out.CommandWithoutProofRouteCandidateCount = len(missingCandidates)
	out.CommandsWithoutDeclaredSemanticFalsifierRoute = missingDeclaredSemanticRoutes
	out.CommandWithoutDeclaredSemanticFalsifierRouteCount = len(missingDeclaredSemanticRoutes)
	out.CommandsWithoutExecutionBackedSemanticRoute = missingExecutionBackedSemanticRoutes
	out.CommandWithoutExecutionBackedSemanticRouteCount = len(missingExecutionBackedSemanticRoutes)
	return out
}

func unknownCommandRefs(refs, known map[string]struct{}) []string {
	unknown := []string{}
	for ref := range refs {
		if _, ok := known[ref]; !ok {
			unknown = append(unknown, ref)
		}
	}
	sort.Strings(unknown)
	return unknown
}

func requireCommandRouteInventoryClosure(metrics commandRouteMetrics) error {
	digestsValid := isSHA256Text(metrics.CommandOracleCandidateSetDigest) &&
		isSHA256Text(metrics.CommandOracleCounterfeitCorpusDigest) &&
		isSHA256Text(metrics.CommandOracleRecordDigest) &&
		isSHA256Text(metrics.CommandOracleSourceSnapshotDigest)
	if len(metrics.CommandsWithoutProofRouteCandidate) == 0 &&
		len(metrics.UnknownProofRouteCandidateRefs) == 0 &&
		len(metrics.UnknownDeclaredSemanticRouteCommandRefs) == 0 &&
		len(metrics.CommandsWithoutExecutionBackedSemanticRoute) == 0 &&
		len(metrics.UnknownExecutionBackedSemanticRouteCommandRefs) == 0 &&
		len(metrics.ContractOnlyCommands) == 0 &&
		len(metrics.RouteOnlyCommands) == 0 &&
		metrics.ExecutionBackedSemanticRouteEntryCount == metrics.ProofRouteCandidateInventoryEntryCount &&
		digestsValid {
		return nil
	}
	return fmt.Errorf("command proof-route inventory defects: missingCandidates=%v unknownCandidateRefs=%v unknownDeclaredSemanticRouteRefs=%v missingExecutionBackedRoutes=%v unknownExecutionBackedRefs=%v executionEntries=%d candidateEntries=%d commandOracleDigestsValid=%t contractOnly=%v routeOnly=%v",
		metrics.CommandsWithoutProofRouteCandidate,
		metrics.UnknownProofRouteCandidateRefs,
		metrics.UnknownDeclaredSemanticRouteCommandRefs,
		metrics.CommandsWithoutExecutionBackedSemanticRoute,
		metrics.UnknownExecutionBackedSemanticRouteCommandRefs,
		metrics.ExecutionBackedSemanticRouteEntryCount,
		metrics.ProofRouteCandidateInventoryEntryCount,
		digestsValid,
		metrics.ContractOnlyCommands,
		metrics.RouteOnlyCommands,
	)
}

func isSHA256Text(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
