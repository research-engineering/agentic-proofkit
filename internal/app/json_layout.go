package app

import (
	"fmt"
	"io"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

type layoutWriter struct {
	io.Writer
	layout stablejson.Layout
}

func parseProcessOptions(args []string) ([]string, stablejson.Layout, bool, error) {
	layout := stablejson.LayoutPretty
	explicit := false
	for len(args) > 0 && args[0] == "--json-layout" {
		if explicit {
			return nil, "", false, fmt.Errorf("--json-layout may be specified only once")
		}
		if len(args) < 2 {
			return nil, "", false, fmt.Errorf("--json-layout requires pretty or compact")
		}
		layout = stablejson.Layout(args[1])
		if layout != stablejson.LayoutPretty && layout != stablejson.LayoutCompact {
			return nil, "", false, fmt.Errorf("--json-layout must be pretty or compact")
		}
		explicit = true
		args = args[2:]
	}
	return args, layout, explicit, nil
}

func jsonLayoutFromWriter(writer io.Writer) stablejson.Layout {
	if typed, ok := writer.(layoutWriter); ok {
		return typed.layout
	}
	return stablejson.LayoutPretty
}

func validateJSONLayoutUse(descriptor commandDescriptor, parsed descriptorArguments, explicit bool) error {
	if !explicit {
		return nil
	}
	if !slices.Contains(descriptor.outputModes, "json") {
		return fmt.Errorf("--json-layout is valid only for JSON command output")
	}
	if descriptor.name == "requirement-browser-server" && parsed.present["--serve"] {
		return fmt.Errorf("--json-layout is invalid when requirement-browser-server serves a browser session")
	}
	for _, format := range parsed.values["--format"] {
		if format != "json" {
			return fmt.Errorf("--json-layout is valid only with --format json")
		}
	}
	return nil
}
