package witnessschedulerplan

import (
	"slices"
	"strings"
)

type conflictCause struct {
	message, resource string
}

func parallelGroupFailures(groups []executionGroup, policies map[string]policy) []string {
	failures := []string{}
	for _, group := range groups {
		for cause := range parallelConflictCauses(group.CommandIDs, policies) {
			failures = append(failures, "parallel group "+group.ParallelGroup+" "+cause.message+cause.resource)
		}
	}
	return failures
}

func parallelConflictCauses(commandIDs []string, policies map[string]policy) map[conflictCause]struct{} {
	causes := map[conflictCause]struct{}{}
	locks, reads, writes := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	destructive, hasOutputs := false, false
	count := 0
	for _, id := range commandIDs {
		p, ok := policies[id]
		if !ok {
			continue
		}
		count++
		destructive = destructive || p.SideEffectClass == "destructive"
		hasOutputs = hasOutputs || len(p.OutputSelectors) != 0
		for _, lock := range p.ExclusiveLocks {
			if _, seen := locks[lock]; seen {
				causes[conflictCause{"has exclusive lock collision ", lock}] = struct{}{}
			}
			locks[lock] = struct{}{}
		}
		for _, resource := range p.ResourceReads {
			if _, seen := writes[resource]; seen {
				causes[conflictCause{"has write/read resource collision ", resource}] = struct{}{}
			}
		}
		for _, resource := range p.ResourceWrites {
			if _, seen := reads[resource]; seen {
				causes[conflictCause{"has read/write resource collision ", resource}] = struct{}{}
			}
			if _, seen := writes[resource]; seen {
				causes[conflictCause{"has write/write resource collision ", resource}] = struct{}{}
			}
			writes[resource] = struct{}{}
		}
		for _, resource := range p.ResourceReads {
			reads[resource] = struct{}{}
		}
	}
	if destructive && count > 1 {
		causes[conflictCause{message: "must not run destructive commands concurrently"}] = struct{}{}
	}
	if hasOutputs && count > 1 {
		outputOverlap, mixedOverlap := parallelSelectorConflicts(commandIDs, policies)
		if outputOverlap {
			causes[conflictCause{message: "has overlapping output selectors"}] = struct{}{}
		}
		if mixedOverlap {
			causes[conflictCause{message: "has overlapping input and output selectors"}] = struct{}{}
		}
	}
	return causes
}

type selectorScope struct {
	prefix  string
	command int
	output  bool
}

type selectorOwners struct {
	first    int
	multiple bool
}

func (owners *selectorOwners) add(command int) {
	if owners.first == 0 {
		owners.first = command
	} else if owners.first != command {
		owners.multiple = true
	}
}

func (owners selectorOwners) hasOther(command int) bool {
	return owners.multiple || owners.first != 0 && owners.first != command
}

type selectorFrame struct {
	prefix          string
	inputs, outputs selectorOwners
}

func parallelSelectorConflicts(commandIDs []string, policies map[string]policy) (outputOverlap, mixedOverlap bool) {
	var scopes []selectorScope
	for i, id := range commandIDs {
		p := policies[id]
		for _, input := range p.InputSelectors {
			scopes = append(scopes, selectorScope{selectorPrefix(input), i + 1, false})
		}
		for _, output := range p.OutputSelectors {
			scopes = append(scopes, selectorScope{selectorPrefix(output), i + 1, true})
		}
	}
	slices.SortFunc(scopes, func(a, b selectorScope) int { return strings.Compare(a.prefix, b.prefix) })
	var stack []selectorFrame
	for _, scope := range scopes {
		// Lexical prefix descendants are contiguous; the surviving frame
		// aggregates just the earlier equal or ancestor owners.
		for len(stack) != 0 && !strings.HasPrefix(scope.prefix, stack[len(stack)-1].prefix) {
			stack = stack[:len(stack)-1]
		}
		var frame selectorFrame
		if len(stack) != 0 {
			frame = stack[len(stack)-1]
			if frame.prefix == scope.prefix {
				stack = stack[:len(stack)-1]
			}
		}
		frame.prefix = scope.prefix
		if scope.output {
			outputOverlap = outputOverlap || frame.outputs.hasOther(scope.command)
			mixedOverlap = mixedOverlap || frame.inputs.hasOther(scope.command)
			frame.outputs.add(scope.command)
		} else {
			mixedOverlap = mixedOverlap || frame.outputs.hasOther(scope.command)
			frame.inputs.add(scope.command)
		}
		if outputOverlap && mixedOverlap {
			break
		}
		stack = append(stack, frame)
	}
	return outputOverlap, mixedOverlap
}

// A shared literal prefix before the first wildcard cannot prove disjointness.
func selectorPrefix(value string) string {
	prefix, _, wildcard := strings.Cut(value, "*")
	if wildcard {
		return prefix
	}
	return strings.TrimSuffix(prefix, "/") + "/"
}
