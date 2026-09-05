// Package agentintegration owns portable CLI bootstrap materialization and
// read-only freshness, and explicit managed file lifecycle. Host activation
// remains outside this package's authority.
package agentintegration

import (
	"bytes"
	"fmt"
	"slices"
	"text/template"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/commandroute"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

const (
	MaximumMetadataBytes = 512
	MaximumBodyBytes     = 4096
)

type toolDescriptor struct {
	name string
	path string
}

var tools = []toolDescriptor{
	{name: "claude", path: ".claude/skills/agentic-proofkit/SKILL.md"},
	{name: "codex", path: ".agents/skills/agentic-proofkit/SKILL.md"},
}

var consumedCommands = []string{
	"adopt-plan", "agent-route", "change-workflow-plan", "help",
	"native-evidence-guidance", "next", "status",
}

// Capability binds an existing public invocation contract, not a new schema or
// a claim of complete transitive implementation equivalence.
type Capability struct {
	Command        string
	Route          []string
	ContractDigest string
}

type Document struct {
	tool             string
	path             string
	content          string
	identity         string
	contentDigest    string
	capabilityDigest string
	metadataBytes    int
	bodyBytes        int
}

func Tools() []string {
	result := make([]string, len(tools))
	for index, descriptor := range tools {
		result[index] = descriptor.name
	}
	return result
}

func ConsumedCommands() []string { return slices.Clone(consumedCommands) }

func Source(tool string, capabilities []Capability) (Document, error) {
	var selected toolDescriptor
	for _, descriptor := range tools {
		if descriptor.name == tool {
			selected = descriptor
		}
	}
	if selected.name == "" {
		return Document{}, fmt.Errorf("integration tool must be claude or codex")
	}
	if len(capabilities) != len(consumedCommands) {
		return Document{}, fmt.Errorf("integration requires its exact consumed command set")
	}
	routes := map[string]string{}
	records := make([]any, len(consumedCommands))
	for index, command := range consumedCommands {
		capability := capabilities[index]
		_, digestErr := admit.SHA256Ref(capability.ContractDigest, "integration consumed contract digest")
		if capability.Command != command || !commandroute.Valid(capability.Route) || digestErr != nil {
			return Document{}, fmt.Errorf("integration consumed command identity is invalid")
		}
		routes[command] = commandroute.Text(capability.Route)
		route := make([]any, len(capability.Route))
		for index, token := range capability.Route {
			route[index] = token
		}
		records[index] = map[string]any{"command": command, "route": route, "contractDigest": capability.ContractDigest}
	}
	capabilityDigest, err := digest.StableJSONSHA256Ref(records)
	if err != nil {
		return Document{}, err
	}
	identity, err := digest.StableJSONSHA256Ref(map[string]any{
		"schemaVersion": 1, "tool": selected.name, "targetPath": selected.path,
		"templateDigest": digest.SHA256TextRef(frontmatter + bootstrap), "capabilityDigest": capabilityDigest,
	})
	if err != nil {
		return Document{}, err
	}
	routes["identity"] = identity
	parsed, err := template.New("bootstrap").Option("missingkey=error").Parse(bootstrap)
	if err != nil {
		return Document{}, fmt.Errorf("integration bootstrap template is invalid")
	}
	var body bytes.Buffer
	if err := parsed.Execute(&body, routes); err != nil {
		return Document{}, fmt.Errorf("integration bootstrap rendering failed")
	}
	if len(frontmatter) > MaximumMetadataBytes || body.Len() > MaximumBodyBytes {
		return Document{}, fmt.Errorf("integration bootstrap exceeds its byte budget")
	}
	content := frontmatter + body.String()
	return Document{
		tool: selected.name, path: selected.path, content: content, identity: identity,
		contentDigest: digest.SHA256TextRef(content), capabilityDigest: capabilityDigest,
		metadataBytes: len(frontmatter), bodyBytes: body.Len(),
	}, nil
}

func (document Document) Content() string { return document.content }

func (document Document) JSONValue() map[string]any {
	return map[string]any{
		"schemaVersion": 1, "kind": "proofkit.integration-source.v1",
		"tool": document.tool, "targetPath": document.path, "integrationId": document.identity,
		"content": document.content, "contentDigest": document.contentDigest,
		"capabilityDigest": document.capabilityDigest,
		"metadataBytes":    document.metadataBytes, "bodyBytes": document.bodyBytes,
		"nonClaims": []any{
			"Generation does not install instructions, activate a host skill, or authorize execution.",
			"The identity binds materialization and consumed registered contracts, not every transitive runtime behavior.",
		},
	}
}

const frontmatter = `---
name: agentic-proofkit
description: "Use when repository authority requests Proofkit-governed specification, change planning, evidence, or closeout work. Route to the installed CLI; do not infer governance from file presence alone."
---

`

const bootstrap = `# Proofkit Workflow

<!-- Integration identity: {{index . "identity"}} -->

## Authority And Launcher

Read the nearest repository instructions and the selected task owner. This
bootstrap routes work; it does not replace repository policy or approve actions.
Use the repository-approved, already-installed Proofkit launcher. Resolve its
concrete executable for this session only. If absent or ambiguous, ask the owner;
do not install, download, select a package manager, or guess a launcher.
Below, command routes are arguments to that approved launcher, not shell scripts.

## Start With One Next Action

1. Run {{index . "status"}} --repo-root <repository> for the bounded current state.
2. Run {{index . "next"}} --repo-root <repository> for the next owner-defined action.
3. Read only the references needed for that action. Use {{index . "help"}} <route>
   for exact invocation flags. Do not reconstruct a state table from this file.
4. Obtain missing inputs or authorization from the repository owner. A plan or
   a recovery suggestion is not permission to write files or execute witnesses.

## Plan And Request Detail

Use {{index . "adopt-plan"}} with an explicit owner-selected mode for initial
adoption; do not silently treat existing code as intended behavior. For changes,
use {{index . "change-workflow-plan"}} with admitted caller-owned input.
Use {{index . "agent-route"}} --agent-envelope --agent-envelope-mode brief for
bounded routing after supplying its required input. Follow returned detailAccess
only when a selected action needs detail. Do not cache schemas or fabricate file
references, selectors, proof results, or a missing prerequisite.

## Repository-Specific Evidence

Request {{index . "native-evidence-guidance"}} when creating or assessing local
checks. Bind each promised invariant to its repository owner, an independently
falsifying oracle, an executable native witness, and its environment. Generate
repo-specific scripts only under that owner's rules; this bootstrap contains no
consumer policy or test implementation. Run authorized native checks and retain
their actual outcomes. Admitted metadata and generated reports do not prove
execution, complete coverage, merge approval, publication, or production readiness.
Stop on failed, unknown, or stale evidence instead of promoting it to success.
`
