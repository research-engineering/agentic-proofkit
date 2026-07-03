package requirementbrowser

import (
	"fmt"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementproofview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	defaultHost = "127.0.0.1"
	defaultPort = 4177
)

var serverNonClaims = []string{
	"Requirement browser servers are local presentation adapters only.",
	"Requirement browser servers do not scan repository state.",
	"Requirement browser servers do not execute native witnesses.",
	"Requirement browser servers do not prove receipt freshness, merge approval, or rollout readiness.",
	"Requirement browser servers do not persist browser annotations into source files.",
}

type Options struct {
	EmptyLocalEnvironmentPolicy bool
	Host                        string
	LocalEnvironmentClasses     []string
	Open                        bool
	Port                        int
	PortSet                     bool
	ProofViewScope              string
	View                        string
}

func BuildPlan(raw any, options Options) (map[string]any, int, error) {
	if options.Host == "" {
		options.Host = defaultHost
	}
	if !options.PortSet {
		options.Port = defaultPort
	}
	if err := admitLoopbackHost(options.Host); err != nil {
		return nil, 1, err
	}
	if err := admitPort(options.Port); err != nil {
		return nil, 1, err
	}
	rendered, err := render(raw, options)
	if err != nil {
		return nil, 1, err
	}
	return map[string]any{
		"authority":         "presentation_adapter_plan",
		"host":              options.Host,
		"htmlByteLength":    len([]byte(rendered.html)),
		"nonClaims":         admit.StringSliceToAny(serverNonClaims),
		"planKind":          "proofkit.requirement-browser-server-plan",
		"port":              options.Port,
		"renderedAuthority": rendered.authority,
		"renderedViewKind":  rendered.viewKind,
		"schemaVersion":     1,
		"url":               browserURL(options.Host, options.Port),
		"view":              options.View,
	}, 0, nil
}

type renderedView struct {
	authority string
	html      string
	viewKind  string
}

func render(raw any, options Options) (renderedView, error) {
	if options.View == "source" {
		view, _, err := requirementsourceview.BuildJSON(raw)
		if err != nil {
			return renderedView{}, err
		}
		html, _, err := requirementsourceview.BuildHTML(raw)
		if err != nil {
			return renderedView{}, err
		}
		record := view.(map[string]any)
		return renderedView{
			authority: stringValue(record["authority"]),
			html:      html,
			viewKind:  stringValue(record["viewKind"]),
		}, nil
	}
	if options.View == "coverage" {
		view, _, err := requirementcoverageview.BuildJSON(raw, requirementcoverageview.Options{})
		if err != nil {
			return renderedView{}, err
		}
		html, _, err := requirementcoverageview.BuildHTML(raw)
		if err != nil {
			return renderedView{}, err
		}
		record := view.(map[string]any)
		return renderedView{
			authority: stringValue(record["authority"]),
			html:      html,
			viewKind:  stringValue(record["viewKind"]),
		}, nil
	}
	if options.View == "spec-tree" {
		view, _, err := requirementspectree.BuildViewJSON(raw)
		if err != nil {
			return renderedView{}, err
		}
		html, _, err := requirementspectree.BuildViewHTML(raw)
		if err != nil {
			return renderedView{}, err
		}
		record := view.(map[string]any)
		return renderedView{
			authority: stringValue(record["authority"]),
			html:      html,
			viewKind:  stringValue(record["viewKind"]),
		}, nil
	}
	if options.View != "proof" {
		return renderedView{}, fmt.Errorf("requirement-browser-server requires --view source, proof, coverage, or spec-tree")
	}
	compact := requirementproofview.IsCompact(raw)
	if compact && len(options.LocalEnvironmentClasses) == 0 && !options.EmptyLocalEnvironmentPolicy {
		return renderedView{}, fmt.Errorf("compact requirement browser proof view requires --local-environment-class or --empty-local-environment-policy")
	}
	viewOptions := requirementproofview.Options{
		Scope:                   options.ProofViewScope,
		LocalEnvironmentClasses: options.LocalEnvironmentClasses,
	}
	view, _, err := requirementproofview.BuildJSON(raw, viewOptions)
	if err != nil {
		return renderedView{}, err
	}
	html, _, err := requirementproofview.BuildHTML(raw, viewOptions)
	if err != nil {
		return renderedView{}, err
	}
	record := view.(map[string]any)
	return renderedView{
		authority: stringValue(record["authority"]),
		html:      html,
		viewKind:  stringValue(record["viewKind"]),
	}, nil
}

func admitLoopbackHost(value string) error {
	if value != "127.0.0.1" && value != "::1" {
		return fmt.Errorf("requirement browser server host must be loopback literal: 127.0.0.1 or ::1")
	}
	return nil
}

func admitPort(value int) error {
	if value < 0 || value > 65535 {
		return fmt.Errorf("requirement browser server port must be an integer from 0 to 65535")
	}
	return nil
}

func browserURL(host string, port int) string {
	hostname := host
	if strings.Contains(host, ":") {
		hostname = "[" + host + "]"
	}
	return fmt.Sprintf("http://%s:%d/", hostname, port)
}

func stringValue(raw any) string {
	if value, ok := raw.(string); ok {
		return value
	}
	return ""
}
