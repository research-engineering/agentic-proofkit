package installedclicontract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/commandroute"
)

const (
	MaximumContractBytes = 1 << 20
	MaximumCommands      = 512
	MaximumPresetIDs     = 128
	maximumHelpBytes     = 256 << 10
)

// Contract is the admitted package-artifact projection needed by installed
// consumer witnesses. Its accessors return copies so callers cannot mutate it.
type Contract struct {
	commandIDsByRoute map[string]string
	presetIDs         []string
}

type HelpIdentity struct {
	CommandID string
	Route     string
}

func Admit(content []byte) (Contract, error) {
	if len(content) == 0 || len(content) > MaximumContractBytes {
		return Contract{}, fmt.Errorf("installed CLI contract size must be between 1 and %d bytes", MaximumContractBytes)
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return Contract{}, fmt.Errorf("decode installed CLI contract: %w", err)
	}
	record, ok := value.(map[string]any)
	if !ok {
		return Contract{}, fmt.Errorf("installed CLI contract must be an object")
	}
	if err := admitCommandRouteGrammar(record); err != nil {
		return Contract{}, err
	}
	commands, ok := record["commands"].([]any)
	if !ok || len(commands) == 0 || len(commands) > MaximumCommands {
		return Contract{}, fmt.Errorf("installed CLI contract commands must contain between 1 and %d entries", MaximumCommands)
	}

	commandIDsByRoute := make(map[string]string, len(commands))
	seenCommandIDs := make(map[string]struct{}, len(commands))
	admittedRoutes := make([]string, 0, len(commands))
	var presetIDs []string
	for index, raw := range commands {
		command, ok := raw.(map[string]any)
		if !ok {
			return Contract{}, fmt.Errorf("installed CLI contract command %d must be an object", index)
		}
		commandID, ok := command["command"].(string)
		if !ok || !commandroute.ValidToken(commandID) {
			return Contract{}, fmt.Errorf("installed CLI contract command %d has an invalid command id", index)
		}
		if _, exists := seenCommandIDs[commandID]; exists {
			return Contract{}, fmt.Errorf("installed CLI contract duplicates a command id")
		}
		seenCommandIDs[commandID] = struct{}{}

		var explicitRoute []string
		if rawRoute, exists := command["route"]; exists {
			route, ok := rawRoute.([]any)
			if !ok {
				return Contract{}, fmt.Errorf("installed CLI contract command %d has an invalid route", index)
			}
			explicitRoute = make([]string, 0, len(route))
			for _, rawToken := range route {
				token, ok := rawToken.(string)
				if !ok {
					return Contract{}, fmt.Errorf("installed CLI contract command %d has an invalid route token", index)
				}
				explicitRoute = append(explicitRoute, token)
			}
		}
		routeTokens, ok := commandroute.Resolve(commandID, explicitRoute)
		if !ok {
			return Contract{}, fmt.Errorf("installed CLI contract command %d has an invalid route", index)
		}
		routeText := commandroute.Text(routeTokens)
		if _, exists := commandIDsByRoute[routeText]; exists {
			return Contract{}, fmt.Errorf("installed CLI contract duplicates a command route")
		}
		commandIDsByRoute[routeText] = commandID
		admittedRoutes = append(admittedRoutes, routeText)

		if commandID == "stack-preset" {
			if presetIDs != nil {
				return Contract{}, fmt.Errorf("installed CLI contract duplicates the stack-preset command")
			}
			var err error
			presetIDs, err = admitPresetIDs(command)
			if err != nil {
				return Contract{}, err
			}
		}
	}
	sort.Strings(admittedRoutes)
	for index := 1; index < len(admittedRoutes); index++ {
		if strings.HasPrefix(admittedRoutes[index], admittedRoutes[index-1]+" ") {
			return Contract{}, fmt.Errorf("installed CLI contract has ambiguous command route prefixes")
		}
	}
	return Contract{commandIDsByRoute: commandIDsByRoute, presetIDs: presetIDs}, nil
}

func admitCommandRouteGrammar(contract map[string]any) error {
	processContract, ok := contract["processContract"].(map[string]any)
	if !ok {
		return fmt.Errorf("installed CLI contract processContract must be an object")
	}
	grammar, ok := processContract["commandRouteGrammar"].(map[string]any)
	if !ok || len(grammar) != 6 {
		return fmt.Errorf("installed CLI contract commandRouteGrammar must contain exactly six fields")
	}
	for _, key := range []string{"ambiguityPolicy", "maximumTokens", "minimumTokens", "omittedRoutePolicy", "separator", "tokenPattern"} {
		if _, exists := grammar[key]; !exists {
			return fmt.Errorf("installed CLI contract commandRouteGrammar is missing %s", key)
		}
	}
	minimum, minimumOK := exactPositiveInteger(grammar["minimumTokens"])
	maximum, maximumOK := exactPositiveInteger(grammar["maximumTokens"])
	if !minimumOK || !maximumOK || minimum != commandroute.MinimumTokens || maximum != commandroute.MaximumTokens ||
		grammar["separator"] != commandroute.Separator || grammar["tokenPattern"] != commandroute.TokenPattern ||
		grammar["ambiguityPolicy"] != commandroute.AmbiguityPolicy || grammar["omittedRoutePolicy"] != commandroute.OmittedRoutePolicy {
		return fmt.Errorf("installed CLI contract commandRouteGrammar differs from the supported process grammar")
	}
	return nil
}

func exactPositiveInteger(value any) (int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	result, err := strconv.Atoi(number.String())
	return result, err == nil && result > 0
}

func (contract Contract) AdmitRouteText(text string) ([]string, error) {
	tokens, ok := commandroute.Parse(text)
	if !ok {
		return nil, fmt.Errorf("installed CLI command route does not match commandRouteGrammar")
	}
	return tokens, nil
}

// AdmitHelpIdentity extracts the exact public command identity from one leaf
// help response. Package verifiers use it to prove route-to-command ownership,
// not merely route-set equality.
func (contract Contract) AdmitHelpIdentity(content []byte) (HelpIdentity, error) {
	if len(content) == 0 || len(content) > maximumHelpBytes || !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 {
		return HelpIdentity{}, fmt.Errorf("installed CLI leaf help is not bounded UTF-8 text")
	}
	lines := strings.Split(string(content), "\n")
	commandID, commandCount := helpField(lines, "Command ID:")
	route, routeCount := helpField(lines, "Route:")
	if commandCount != 1 || routeCount != 1 || !commandroute.ValidToken(commandID) {
		return HelpIdentity{}, fmt.Errorf("installed CLI leaf help identity is invalid")
	}
	if _, err := contract.AdmitRouteText(route); err != nil {
		return HelpIdentity{}, fmt.Errorf("installed CLI leaf help route is invalid")
	}
	return HelpIdentity{CommandID: commandID, Route: route}, nil
}

func helpField(lines []string, label string) (string, int) {
	value := ""
	count := 0
	for index, line := range lines {
		if line != label {
			continue
		}
		count++
		if index+1 < len(lines) && strings.HasPrefix(lines[index+1], "  ") && !strings.HasPrefix(lines[index+1], "   ") {
			value = strings.TrimPrefix(lines[index+1], "  ")
		}
	}
	return value, count
}

func (contract Contract) CommandIDsByRoute() map[string]string {
	result := make(map[string]string, len(contract.commandIDsByRoute))
	for route, commandID := range contract.commandIDsByRoute {
		result[route] = commandID
	}
	return result
}

func (contract Contract) PresetIDs() ([]string, error) {
	if len(contract.presetIDs) == 0 {
		return nil, fmt.Errorf("installed CLI contract omitted stack-preset")
	}
	return append([]string(nil), contract.presetIDs...), nil
}

func admitPresetIDs(command map[string]any) ([]string, error) {
	output, ok := command["outputContract"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("installed CLI contract stack-preset outputContract must be an object")
	}
	choices, ok := output["flagChoices"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("installed CLI contract stack-preset flagChoices must be an object")
	}
	rawIDs, ok := choices["--preset"].([]any)
	if !ok || len(rawIDs) == 0 || len(rawIDs) > MaximumPresetIDs {
		return nil, fmt.Errorf("installed CLI contract stack-preset choices must contain between 1 and %d entries", MaximumPresetIDs)
	}
	ids := make([]string, 0, len(rawIDs))
	seen := make(map[string]struct{}, len(rawIDs))
	for _, rawID := range rawIDs {
		id, ok := rawID.(string)
		if !ok || id == "" {
			return nil, fmt.Errorf("installed CLI contract stack-preset choices must be non-empty strings")
		}
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("installed CLI contract stack-preset choices must be unique")
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if !sort.StringsAreSorted(ids) {
		return nil, fmt.Errorf("installed CLI contract stack-preset choices must be sorted")
	}
	return ids, nil
}
