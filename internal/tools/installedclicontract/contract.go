package installedclicontract

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

const (
	MaximumContractBytes      = 1 << 20
	MaximumCommands           = 512
	MaximumPresetIDs          = 128
	maximumCommandRouteTokens = 4
	maximumHelpBytes          = 256 << 10
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
		if !ok || !ValidRouteToken(commandID) {
			return Contract{}, fmt.Errorf("installed CLI contract command %d has an invalid command id", index)
		}
		if _, exists := seenCommandIDs[commandID]; exists {
			return Contract{}, fmt.Errorf("installed CLI contract duplicates a command id")
		}
		seenCommandIDs[commandID] = struct{}{}

		routeTokens := []string{commandID}
		if rawRoute, exists := command["route"]; exists {
			route, ok := rawRoute.([]any)
			if !ok || len(route) == 0 || len(route) > maximumCommandRouteTokens {
				return Contract{}, fmt.Errorf("installed CLI contract command %d has an invalid route", index)
			}
			routeTokens = make([]string, 0, len(route))
			for _, rawToken := range route {
				token, ok := rawToken.(string)
				if !ok || !ValidRouteToken(token) {
					return Contract{}, fmt.Errorf("installed CLI contract command %d has an invalid route token", index)
				}
				routeTokens = append(routeTokens, token)
			}
		}
		routeText := strings.Join(routeTokens, " ")
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

// AdmitHelpIdentity extracts the exact public command identity from one leaf
// help response. Package verifiers use it to prove route-to-command ownership,
// not merely route-set equality.
func AdmitHelpIdentity(content []byte) (HelpIdentity, error) {
	if len(content) == 0 || len(content) > maximumHelpBytes || !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 {
		return HelpIdentity{}, fmt.Errorf("installed CLI leaf help is not bounded UTF-8 text")
	}
	lines := strings.Split(string(content), "\n")
	commandID, commandCount := helpField(lines, "Command ID:")
	route, routeCount := helpField(lines, "Route:")
	if commandCount != 1 || routeCount != 1 || !ValidRouteToken(commandID) {
		return HelpIdentity{}, fmt.Errorf("installed CLI leaf help identity is invalid")
	}
	routeTokens := strings.Split(route, " ")
	if len(routeTokens) == 0 || len(routeTokens) > maximumCommandRouteTokens {
		return HelpIdentity{}, fmt.Errorf("installed CLI leaf help route is invalid")
	}
	for _, token := range routeTokens {
		if !ValidRouteToken(token) {
			return HelpIdentity{}, fmt.Errorf("installed CLI leaf help route is invalid")
		}
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

func ValidRouteToken(token string) bool {
	if token == "" || token[0] == '-' || token[len(token)-1] == '-' {
		return false
	}
	previousHyphen := false
	for _, value := range token {
		if value == '-' {
			if previousHyphen {
				return false
			}
			previousHyphen = true
			continue
		}
		if (value < 'a' || value > 'z') && (value < '0' || value > '9') {
			return false
		}
		previousHyphen = false
	}
	return true
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
