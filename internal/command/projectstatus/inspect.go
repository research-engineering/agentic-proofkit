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

func inspectWithDependencies(ctx context.Context, repositoryRoot string, dependencies inspectionDependencies) (Status, error) {
	if dependencies.inspectControl == nil || dependencies.readFile == nil {
		return Status{}, fmt.Errorf("project status inspection dependencies are incomplete")
	}
	for attempt := 0; attempt < 2; attempt++ {
		status, err := inspectAttempt(ctx, repositoryRoot, dependencies)
		if err == nil {
			return status, nil
		}
		if !errors.Is(err, errSnapshotChanged) && !errors.Is(err, repositorytransaction.ErrControlStateChanged) {
			return Status{}, err
		}
	}
	return Status{}, fmt.Errorf("project status repository changed during both bounded inspection attempts")
}

func inspectAttempt(ctx context.Context, repositoryRoot string, dependencies inspectionDependencies) (status Status, returnErr error) {
	lease, err := repositorytransaction.OpenInspectionLease(ctx, repositoryRoot)
	if err != nil {
		return Status{}, err
	}
	closeLease := dependencies.closeLease
	if closeLease == nil {
		closeLease = defaultInspectionDependencies.closeLease
	}
	defer func() {
		if closeErr := closeLease(lease); closeErr != nil {
			status = Status{}
			returnErr = fmt.Errorf("close project status inspection: %w", closeErr)
		}
	}()
	before, err := dependencies.inspectControl(ctx, lease)
	if err != nil {
		return Status{}, err
	}
	if err := lease.VerifyRootIdentity(); err != nil {
		return Status{}, err
	}
	transaction, err := observeTransaction(before)
	if err != nil {
		return Status{}, err
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
			return Status{}, err
		}
		if err := verifyCohort(ctx, lease, cohort, dependencies.readFile); err != nil {
			return Status{}, err
		}
	}
	after, err := dependencies.inspectControl(ctx, lease)
	if err != nil {
		return Status{}, err
	}
	if before != after {
		return Status{}, errSnapshotChanged
	}
	if err := lease.VerifyRootIdentity(); err != nil {
		return Status{}, err
	}
	return evaluate(snapshot)
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
	children, closure, childCohort, err := inspectChildren(ctx, lease, manifest, budget, readFile)
	if err != nil {
		return inspectionSnapshot{}, nil, err
	}
	cohort = append(cohort, childCohort...)
	snapshot.Children = children
	snapshot.ClosureState = closure
	return snapshot, cohort, nil
}

func inspectChildren(ctx context.Context, lease *repositorytransaction.InspectionLease, manifest adoptionmaterialization.Manifest, budget *readBudget, readFile projectFileReader) ([]childObservation, ClosureState, []cohortEntry, error) {
	observations := make(map[string]fileObservation, len(manifest.Routes))
	records := make([]adoptionmaterialization.RoutedProjectRecord, 0, len(manifest.Routes))
	cohort := make([]cohortEntry, 0, len(manifest.Routes))
	for _, route := range manifest.Routes {
		file, err := readFile(ctx, lease, route.Path, budget)
		if err != nil {
			return nil, ClosureNotEvaluated, nil, err
		}
		observations[route.Path] = file
		cohort = append(cohort, cohortEntry{digest: file.digest, path: route.Path, state: file.state})
		if file.state == fileRead {
			records = append(records, adoptionmaterialization.RoutedProjectRecord{Content: file.content, Path: route.Path})
		}
	}
	admissionResult, err := adoptionmaterialization.AdmitMaterializedProject(manifest, records)
	if err != nil {
		return nil, ClosureNotEvaluated, nil, err
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
			return nil, ClosureNotEvaluated, nil, fmt.Errorf("project status file owner returned an unsupported state")
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
	return children, closure, cohort, nil
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
