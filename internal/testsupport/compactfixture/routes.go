package compactfixture

import (
	"encoding/json"
	"sort"
	"strconv"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
)

type Routes struct {
	BindingRecordID       string
	FalsificationRouteID  string
	FalsificationSelector string
	PositiveRouteID       string
	PositiveSelector      string
}

func MustRoutes(identity compactproofcontract.BindingIdentity, positiveSelector, falsificationSelector string) Routes {
	bindingRecordID, err := compactproofcontract.BindingRecordID(identity)
	if err != nil {
		panic(err)
	}
	positiveRouteID, err := compactproofcontract.WitnessRouteID(bindingRecordID, compactproofcontract.PositiveWitnessRole, positiveSelector)
	if err != nil {
		panic(err)
	}
	falsificationRouteID, err := compactproofcontract.WitnessRouteID(bindingRecordID, compactproofcontract.FalsificationWitnessRole, falsificationSelector)
	if err != nil {
		panic(err)
	}
	return Routes{
		BindingRecordID: bindingRecordID, FalsificationRouteID: falsificationRouteID,
		FalsificationSelector: falsificationSelector, PositiveRouteID: positiveRouteID,
		PositiveSelector: positiveSelector,
	}
}

func (routes Routes) Values(environmentClasses, verifyCommands []string) []any {
	values := []map[string]any{
		routes.value(compactproofcontract.FalsificationWitnessRole, routes.FalsificationSelector, routes.FalsificationRouteID, 1, environmentClasses, verifyCommands),
		routes.value(compactproofcontract.PositiveWitnessRole, routes.PositiveSelector, routes.PositiveRouteID, 0, environmentClasses, verifyCommands),
	}
	sort.Slice(values, func(left, right int) bool {
		return values[left]["witnessRouteId"].(string) < values[right]["witnessRouteId"].(string)
	})
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func (routes Routes) value(role, selector, routeID string, order int, environmentClasses, verifyCommands []string) map[string]any {
	return map[string]any{
		"bindingRecordId":      routes.BindingRecordID,
		"environmentClasses":   stringsToAny(environmentClasses),
		"resolutionOrderIndex": json.Number(strconv.Itoa(order)),
		"role":                 role,
		"selector":             selector,
		"verifyCommands":       stringsToAny(verifyCommands),
		"witnessRouteId":       routeID,
	}
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
