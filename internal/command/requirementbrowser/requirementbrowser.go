package requirementbrowser

import (
	"fmt"
	"strings"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementproofview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	defaultHost = "127.0.0.1"
	defaultPort = 0
)

var serverNonClaims = []string{
	"Requirement browser servers are local presentation adapters only.",
	"Requirement browser servers do not scan repository state.",
	"Requirement browser servers do not execute native witnesses.",
	"Requirement browser servers do not prove receipt freshness, merge approval, or rollout readiness.",
	"Requirement browser servers do not persist browser annotations into source files.",
	"Requirement browser servers do not authenticate the surrounding browser profile or operating-system user.",
}

type Options struct {
	EmptyLocalEnvironmentPolicy bool
	Host                        string
	LocalEnvironmentClasses     []string
	Open                        bool
	Port                        int
	PortSet                     bool
	ProofViewScope              string
	SessionMode                 string
	SessionTimeout              time.Duration
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
	portSelection := "fixed"
	var plannedURL any = browserURL(options.Host, options.Port)
	if options.Port == 0 {
		portSelection = "ephemeral"
		plannedURL = nil
	}
	return map[string]any{
		"authority":         "presentation_adapter_plan",
		"host":              options.Host,
		"htmlByteLength":    len([]byte(rendered.html)),
		"nonClaims":         admit.StringSliceToAny(serverNonClaims),
		"planKind":          "proofkit.requirement-browser-server-plan",
		"port":              options.Port,
		"portSelection":     portSelection,
		"renderedAuthority": rendered.authority,
		"renderedViewKind":  rendered.viewKind,
		"schemaVersion":     1,
		"url":               plannedURL,
		"view":              options.View,
	}, 0, nil
}

type renderedView struct {
	authority string
	html      string
	viewKind  string
	workspace *workspaceSession
}

func render(raw any, options Options) (renderedView, error) {
	if options.View == "workspace" {
		session, document, err := buildWorkspace(raw)
		if err != nil {
			return renderedView{}, err
		}
		return renderedView{authority: "presentation_adapter", html: document, viewKind: "proofkit.requirement-workspace", workspace: &session}, nil
	}
	if options.View == "source" {
		view, html, err := requirementsourceview.BuildBrowserDocument(raw)
		if err != nil {
			return renderedView{}, err
		}
		return renderedView{
			authority: stringValue(view["authority"]),
			html:      html,
			viewKind:  stringValue(view["viewKind"]),
		}, nil
	}
	if options.View == "coverage" {
		view, html, err := requirementcoverageview.BuildBrowserDocument(raw)
		if err != nil {
			return renderedView{}, err
		}
		return renderedView{
			authority: stringValue(view["authority"]),
			html:      html,
			viewKind:  stringValue(view["viewKind"]),
		}, nil
	}
	if options.View == "spec-tree" {
		view, html, err := requirementspectree.BuildBrowserDocument(raw)
		if err != nil {
			return renderedView{}, err
		}
		return renderedView{
			authority: stringValue(view["authority"]),
			html:      html,
			viewKind:  stringValue(view["viewKind"]),
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
	view, html, err := requirementproofview.BuildBrowserDocument(raw, viewOptions)
	if err != nil {
		return renderedView{}, err
	}
	return renderedView{
		authority: stringValue(view["authority"]),
		html:      html,
		viewKind:  stringValue(view["viewKind"]),
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
