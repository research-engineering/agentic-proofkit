package requirementbrowser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/research-engineering/agentic-proofkit/internal/command/projectstatus"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementgraph"
)

func BuildProjectPlan(ctx context.Context, repositoryRoot string, options Options) (map[string]any, int, error) {
	rendered, options, err := prepareProject(ctx, repositoryRoot, options)
	if err != nil {
		return nil, 1, err
	}
	return renderedPlan(rendered, options), 0, nil
}

func StartProjectServer(ctx context.Context, repositoryRoot string, options Options) (ServerHandle, error) {
	rendered, options, err := prepareProject(ctx, repositoryRoot, options)
	if err != nil {
		return ServerHandle{}, err
	}
	if err := ctx.Err(); err != nil {
		return ServerHandle{}, err
	}
	return startRenderedServer(rendered, options)
}

func ServeProject(ctx context.Context, repositoryRoot string, options Options, stdout io.Writer) error {
	handle, err := StartProjectServer(ctx, repositoryRoot, options)
	if err != nil {
		return err
	}
	return serveHandle(ctx, handle, options, stdout)
}

func prepareProject(ctx context.Context, repositoryRoot string, options Options) (renderedView, Options, error) {
	return prepareProjectWithInspector(ctx, repositoryRoot, options, projectstatus.InspectProject)
}

func prepareProjectWithInspector(ctx context.Context, repositoryRoot string, options Options, inspect func(context.Context, string) (projectstatus.Inspection, error)) (renderedView, Options, error) {
	options, err := admitServerAddress(options)
	if err != nil {
		return renderedView{}, Options{}, err
	}
	if options.View != "" && options.View != "workspace" || options.ProofViewScope != "" || options.EmptyLocalEnvironmentPolicy || len(options.LocalEnvironmentClasses) != 0 {
		return renderedView{}, Options{}, fmt.Errorf("project browser does not accept alternate views or proof policies")
	}
	options.View = "workspace"
	if repositoryRoot == "" {
		return renderedView{}, Options{}, fmt.Errorf("view requires an explicit --repo-root")
	}
	inspection, err := inspect(ctx, repositoryRoot)
	if err != nil {
		return renderedView{}, Options{}, fmt.Errorf("view could not inspect the project; use next with the same --repo-root")
	}
	if inspection.Project == nil {
		return renderedView{}, Options{}, fmt.Errorf("view requires a complete admitted project; use next with the same --repo-root")
	}
	snapshot, err := requirementcontext.FromProject(inspection.Project, inspection.ManifestContentDigest)
	if err != nil {
		return renderedView{}, Options{}, fmt.Errorf("view could not prepare bounded project context")
	}
	graph, err := requirementgraph.Build(map[string]any{
		"schemaVersion": json.Number("2"), "graphId": snapshot.CatalogID,
		"context": requirementcontext.SnapshotValue(snapshot),
	})
	if err != nil {
		return renderedView{}, Options{}, fmt.Errorf("view could not prepare the project relation graph")
	}
	session, document, err := prepareWorkspace(snapshot.CatalogID, snapshot, nil, graph, workspaceHTML)
	if err != nil {
		return renderedView{}, Options{}, fmt.Errorf("view could not prepare the project workspace")
	}
	return renderedView{authority: "presentation_adapter", html: document, viewKind: "proofkit.requirement-workspace", workspace: &session}, options, nil
}
