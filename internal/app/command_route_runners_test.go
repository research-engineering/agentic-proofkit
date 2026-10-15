package app

import (
	"slices"
	"testing"
)

func TestCommandRouteRunnersEqualCommandDescriptors(t *testing.T) {
	inventory := CommandRouteRunners()
	if len(inventory) != len(commandDescriptors) {
		t.Fatalf("inventory has %d entries, descriptors %d", len(inventory), len(commandDescriptors))
	}
	byName := map[string]commandDescriptor{}
	for _, descriptor := range commandDescriptors {
		byName[descriptor.name] = descriptor
	}
	for index, entry := range inventory {
		if index > 0 && inventory[index-1].Name >= entry.Name {
			t.Fatalf("inventory is not sorted by unique name at %s", entry.Name)
		}
		descriptor, ok := byName[entry.Name]
		if !ok {
			t.Fatalf("inventory names unknown command %s", entry.Name)
		}
		if !slices.Equal(entry.Route, descriptor.routeTokens) || entry.Runner != string(descriptor.runner) {
			t.Fatalf("%s inventory route %v runner %s, descriptor route %v runner %s", entry.Name, entry.Route, entry.Runner, descriptor.routeTokens, descriptor.runner)
		}
	}
	inventory[0].Route[0] = "mutated"
	if CommandRouteRunners()[0].Route[0] == "mutated" {
		t.Fatal("inventory shares route storage with the descriptors")
	}
}
