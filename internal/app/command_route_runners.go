package app

import "sort"

// CommandRouteRunner is one entry of the CLI dispatcher's route-to-runner
// inventory: a command descriptor's name, route tokens and runner.
type CommandRouteRunner struct {
	Name   string
	Route  []string
	Runner string
}

// CommandRouteRunners returns a copy of the route-to-runner inventory of the
// CLI dispatcher, sorted by name. No CLI path calls it; the out-of-package
// schema completeness reachability oracle slices each route with it.
func CommandRouteRunners() []CommandRouteRunner {
	inventory := make([]CommandRouteRunner, 0, len(commandDescriptors))
	for _, descriptor := range commandDescriptors {
		inventory = append(inventory, CommandRouteRunner{
			Name:   descriptor.name,
			Route:  cloneStrings(descriptor.routeTokens),
			Runner: string(descriptor.runner),
		})
	}
	sort.Slice(inventory, func(left, right int) bool { return inventory[left].Name < inventory[right].Name })
	return inventory
}
