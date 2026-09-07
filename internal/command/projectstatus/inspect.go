package projectstatus

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

type controlInspector func(context.Context, *repositorytransaction.InspectionLease) (repositorytransaction.ControlInspection, error)
type projectFileReader func(context.Context, *repositorytransaction.InspectionLease, string, *readBudget) (fileObservation, error)

type inspectionDependencies struct {
	inspectControl controlInspector
	readFile       projectFileReader
	closeLease     func(*repositorytransaction.InspectionLease) error
}

type cohortEntry struct {
	digest string
	path   string
	state  fileState
}

type childInspection struct {
	children []childObservation
	closure  ClosureState
	cohort   []cohortEntry
	project  *adoptionmaterialization.Project
}

var defaultInspectionDependencies = inspectionDependencies{
	inspectControl: func(ctx context.Context, lease *repositorytransaction.InspectionLease) (repositorytransaction.ControlInspection, error) {
		return lease.InspectControlState(ctx)
	},
	readFile: readProjectFile,
	closeLease: func(lease *repositorytransaction.InspectionLease) error {
		return lease.Close()
	},
}

func Inspect(ctx context.Context, repositoryRoot string) (Status, error) {
	return inspectWithDependencies(ctx, repositoryRoot, defaultInspectionDependencies)
}

func InspectProject(ctx context.Context, repositoryRoot string) (Inspection, error) {
	return inspectProjectWithDependencies(ctx, repositoryRoot, defaultInspectionDependencies)
}

func inspectWithDependencies(ctx context.Context, repositoryRoot string, dependencies inspectionDependencies) (Status, error) {
	inspection, err := inspectProjectWithDependencies(ctx, repositoryRoot, dependencies)
	return inspection.Status, err
}

func inspectProjectWithDependencies(ctx context.Context, repositoryRoot string, dependencies inspectionDependencies) (Inspection, error) {
	if dependencies.inspectControl == nil || dependencies.readFile == nil {
		return Inspection{}, fmt.Errorf("project status inspection dependencies are incomplete")
	}
	for attempt := 0; attempt < 2; attempt++ {
		inspection, err := inspectAttempt(ctx, repositoryRoot, dependencies)
		if err == nil {
			return inspection, nil
		}
		if !errors.Is(err, errSnapshotChanged) && !errors.Is(err, repositorytransaction.ErrControlStateChanged) {
			return Inspection{}, err
		}
	}
	return Inspection{}, fmt.Errorf("project status repository changed during both bounded inspection attempts")
}

func inspectAttempt(ctx context.Context, repositoryRoot string, dependencies inspectionDependencies) (inspection Inspection, returnErr error) {
	lease, err := repositorytransaction.OpenInspectionLease(ctx, repositoryRoot)
	if err != nil {
		return Inspection{}, err
	}
	closeLease := dependencies.closeLease
	if closeLease == nil {
		closeLease = defaultInspectionDependencies.closeLease
	}
	defer func() {
		if closeErr := closeLease(lease); closeErr != nil {
			inspection = Inspection{}
			returnErr = fmt.Errorf("close project status inspection: %w", closeErr)
		}
	}()
	before, err := dependencies.inspectControl(ctx, lease)
	if err != nil {
		return Inspection{}, err
	}
	if err := lease.VerifyRootIdentity(); err != nil {
		return Inspection{}, err
	}
	transaction, err := observeTransaction(before)
	if err != nil {
		return Inspection{}, err
	}
	snapshot := inspectionSnapshot{
		ClosureState: ClosureNotEvaluated,
		Manifest:     manifestObservation{State: ManifestAbsent},
		Transaction:  transaction,
	}
	var cohort []cohortEntry
	if transaction.State == TransactionClean {
		snapshot, cohort, err = inspectProjectFiles(ctx, lease, transaction, dependencies.readFile)
		if err != nil {
			return Inspection{}, err
		}
		if err := verifyCohort(ctx, lease, cohort, dependencies.readFile); err != nil {
			return Inspection{}, err
		}
	}
	after, err := dependencies.inspectControl(ctx, lease)
	if err != nil {
		return Inspection{}, err
	}
	if before != after {
		return Inspection{}, errSnapshotChanged
	}
	if err := lease.VerifyRootIdentity(); err != nil {
		return Inspection{}, err
	}
	if err := ctx.Err(); err != nil {
		return Inspection{}, fmt.Errorf("project status inspection cancelled before evaluation: %w", err)
	}
	status, err := evaluate(snapshot)
	if err != nil {
		return Inspection{}, err
	}
	if err := ctx.Err(); err != nil {
		return Inspection{}, fmt.Errorf("project status inspection cancelled before completion: %w", err)
	}
	return Inspection{ManifestContentDigest: snapshot.Manifest.ContentDigest, Project: snapshot.project, Status: status}, nil
}

func observeTransaction(value repositorytransaction.ControlInspection) (transactionObservation, error) {
	result := transactionObservation{Epoch: value.EpochID, TransactionID: value.TransactionID}
	switch value.State {
	case repositorytransaction.ControlStateClean:
		result.State = TransactionClean
	case repositorytransaction.ControlStateRecoverable:
		result.State = TransactionRecoverable
	case repositorytransaction.ControlStateInvalid:
		result.State = TransactionInvalid
	default:
		return transactionObservation{}, fmt.Errorf("repository transaction owner returned an unsupported control state")
	}
	return result, nil
}

func inspectProjectFiles(ctx context.Context, lease *repositorytransaction.InspectionLease, transaction transactionObservation, readFile projectFileReader) (inspectionSnapshot, []cohortEntry, error) {
	snapshot := inspectionSnapshot{
		ClosureState: ClosureNotEvaluated,
		Manifest:     manifestObservation{State: ManifestAbsent},
		Transaction:  transaction,
	}
	budget := &readBudget{remaining: MaximumAggregateBytes}
	manifestFile, err := readFile(ctx, lease, adoptionmaterialization.ProjectManifestPath, budget)
	if err != nil {
		return inspectionSnapshot{}, nil, err
	}
	cohort := []cohortEntry{{digest: manifestFile.digest, path: adoptionmaterialization.ProjectManifestPath, state: manifestFile.state}}
	switch manifestFile.state {
	case fileMissing:
		return snapshot, cohort, nil
	case fileInvalid:
		snapshot.Manifest.State = ManifestInvalid
		return snapshot, cohort, nil
	case fileRead:
		snapshot.Manifest.ContentDigest = manifestFile.digest
	default:
		return inspectionSnapshot{}, nil, fmt.Errorf("project status file owner returned an unsupported state")
	}
	rawManifest, err := admission.DecodeJSON(bytes.NewReader(manifestFile.content), MaximumFileBytes)
	if err != nil {
		snapshot.Manifest.State = ManifestInvalid
		return snapshot, cohort, nil
	}
	manifest, err := adoptionmaterialization.AdmitManifest(rawManifest)
	if err != nil {
		snapshot.Manifest.State = ManifestInvalid
		return snapshot, cohort, nil
	}
	snapshot.Manifest = manifestObservation{ContentDigest: manifestFile.digest, ManifestID: manifest.ManifestID, State: ManifestAdmitted}
	snapshot.ProjectID = manifest.ProjectID
	children, err := inspectChildren(ctx, lease, manifest, budget, readFile)
	if err != nil {
		return inspectionSnapshot{}, nil, err
	}
	cohort = append(cohort, children.cohort...)
	snapshot.Children = children.children
	snapshot.ClosureState = children.closure
	snapshot.project = children.project
	return snapshot, cohort, nil
}

func inspectChildren(ctx context.Context, lease *repositorytransaction.InspectionLease, manifest adoptionmaterialization.Manifest, budget *readBudget, readFile projectFileReader) (childInspection, error) {
	observations := make(map[string]fileObservation, len(manifest.Routes))
	records := make([]adoptionmaterialization.RoutedProjectRecord, 0, len(manifest.Routes))
	cohort := make([]cohortEntry, 0, len(manifest.Routes))
	for _, route := range manifest.Routes {
		file, err := readFile(ctx, lease, route.Path, budget)
		if err != nil {
			return childInspection{}, err
		}
		observations[route.Path] = file
		cohort = append(cohort, cohortEntry{digest: file.digest, path: route.Path, state: file.state})
		if file.state == fileRead {
			records = append(records, adoptionmaterialization.RoutedProjectRecord{Content: file.content, Path: route.Path})
		}
	}
	admissionResult, err := adoptionmaterialization.AdmitMaterializedProject(manifest, records)
	if err != nil {
		return childInspection{}, err
	}
	admissions := make(map[string]adoptionmaterialization.RoutedProjectRecordAdmission, len(admissionResult.Records))
	for _, item := range admissionResult.Records {
		admissions[item.Path] = item
	}
	children := make([]childObservation, 0, len(manifest.Routes))
	for _, route := range manifest.Routes {
		file := observations[route.Path]
		child := childObservation{ArtifactKind: route.ArtifactKind, ExpectedDigest: route.ArtifactID, ObservedDigest: file.digest}
		switch file.state {
		case fileMissing:
			child.State = ChildMissing
		case fileInvalid:
			child.State = ChildInvalid
		case fileRead:
			admitted := admissions[route.Path]
			switch {
			case !admitted.DigestMatches:
				child.State = ChildDigestMismatch
			case !admitted.Admitted:
				child.State = ChildInvalid
			default:
				child.State = ChildAdmitted
			}
		default:
			return childInspection{}, fmt.Errorf("project status file owner returned an unsupported state")
		}
		children = append(children, child)
	}
	closure := ClosureNotEvaluated
	if admissionResult.ClosureEvaluated {
		closure = ClosureInvalid
		if admissionResult.ClosureAdmitted {
			closure = ClosureAdmitted
		}
	}
	return childInspection{children: children, closure: closure, cohort: cohort, project: admissionResult.Project}, nil
}

func verifyCohort(ctx context.Context, lease *repositorytransaction.InspectionLease, cohort []cohortEntry, readFile projectFileReader) error {
	budget := &readBudget{remaining: MaximumAggregateBytes}
	for _, expected := range cohort {
		observed, err := readFile(ctx, lease, expected.path, budget)
		if err != nil {
			return err
		}
		if observed.state != expected.state || observed.digest != expected.digest {
			return errSnapshotChanged
		}
	}
	return nil
}
