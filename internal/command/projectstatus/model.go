// Package projectstatus owns bounded, read-only classification of a
// materialized Proofkit project and its single next-action projection.
package projectstatus

import (
	"encoding/json"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

const (
	SchemaVersion = 1
	StatusKind    = "proofkit.project-status"
	NextKind      = "proofkit.project-next-action"

	MaximumFileBytes      = repositorytransaction.MaximumFileBytes
	MaximumAggregateBytes = repositorytransaction.MaximumAggregateBytes
	MaximumOutputBytes    = 32 << 10
	MaximumTextBytes      = 4 << 10
	MaximumTextLines      = 16
	MaximumIssueCodes     = 16
)

type ProjectState string

const (
	StateUninitialized        ProjectState = "uninitialized"
	StateRecoveryRequired     ProjectState = "recovery_required"
	StateBlocked              ProjectState = "blocked"
	StateStale                ProjectState = "stale"
	StateVerificationRequired ProjectState = "verification_required"
)

type TransactionState string

const (
	TransactionClean       TransactionState = "clean"
	TransactionRecoverable TransactionState = "recoverable"
	TransactionInvalid     TransactionState = "invalid"
)

type ManifestState string

const (
	ManifestAbsent   ManifestState = "absent"
	ManifestInvalid  ManifestState = "invalid"
	ManifestAdmitted ManifestState = "admitted"
)

type ChildState string

const (
	ChildMissing        ChildState = "missing"
	ChildDigestMismatch ChildState = "digest_mismatch"
	ChildInvalid        ChildState = "invalid"
	ChildAdmitted       ChildState = "admitted"
)

type ClosureState string

const (
	ClosureNotEvaluated ClosureState = "not_evaluated"
	ClosureInvalid      ClosureState = "invalid"
	ClosureAdmitted     ClosureState = "admitted"
)

const (
	IssueTransactionInvalid          = "transaction_control_invalid"
	IssueTransactionRecoveryRequired = "transaction_recovery_required"
	IssueManifestMissing             = "project_manifest_missing"
	IssueManifestInvalid             = "project_manifest_invalid"
	IssueChildMissing                = "project_record_missing"
	IssueChildDigestMismatch         = "project_record_digest_mismatch"
	IssueChildInvalid                = "project_record_invalid"
	IssueClosureInvalid              = "project_cross_record_closure_invalid"
)

const (
	ActionRepairControlState        = "repair_control_state"
	ActionChooseRecovery            = "choose_recovery"
	ActionChooseAdoptionMode        = "choose_adoption_mode"
	ActionRepairProjectRecords      = "repair_project_records"
	ActionRematerializeProject      = "rematerialize_project"
	ActionRunRepositoryVerification = "run_repository_verification"
)

var boundaryNonClaims = []string{
	"Project next actions are derived non-executable guidance; repository owners retain execution and policy authority.",
	"Project status does not approve merge, release, rollout, deployment, or production readiness.",
	"Project status does not execute native witnesses or verify receipt trust, currentness, or scope.",
}

type transactionObservation struct {
	Epoch         string
	State         TransactionState
	TransactionID string
}

type manifestObservation struct {
	ContentDigest string
	ManifestID    string
	State         ManifestState
}

type childObservation struct {
	ArtifactKind   string
	ExpectedDigest string
	ObservedDigest string
	State          ChildState
}

type inspectionSnapshot struct {
	Children     []childObservation
	ClosureState ClosureState
	Manifest     manifestObservation
	ProjectID    string
	Transaction  transactionObservation
}

type NextAction struct {
	ActionClass      string
	ActionID         string
	CommandRoute     []string
	ContextRef       string
	Executable       bool
	RequiredDecision string
}

type Status struct {
	IssueCodes   []string
	ManifestID   string
	NextAction   NextAction
	ProjectID    string
	ProjectState ProjectState
	SnapshotID   string
	StatusID     string
}

type Next struct {
	Action       NextAction
	IssueCodes   []string
	PacketID     string
	ProjectState ProjectState
	SnapshotID   string
	StatusRef    string
}

func (snapshot inspectionSnapshot) identityValue() map[string]any {
	children := make([]any, 0, len(snapshot.Children))
	for _, child := range snapshot.Children {
		children = append(children, map[string]any{
			"artifactKind":   child.ArtifactKind,
			"expectedDigest": child.ExpectedDigest,
			"observedDigest": nullable(child.ObservedDigest),
			"state":          string(child.State),
		})
	}
	project := map[string]any{"state": "unknown"}
	if snapshot.ProjectID != "" {
		project = map[string]any{"projectId": snapshot.ProjectID, "state": "admitted"}
	}
	return map[string]any{
		"children":     children,
		"closureState": string(snapshot.ClosureState),
		"manifest": map[string]any{
			"contentDigest": nullable(snapshot.Manifest.ContentDigest),
			"manifestId":    nullable(snapshot.Manifest.ManifestID),
			"state":         string(snapshot.Manifest.State),
		},
		"project":       project,
		"schemaVersion": json.Number("1"),
		"transaction": map[string]any{
			"epoch":         snapshot.Transaction.Epoch,
			"state":         string(snapshot.Transaction.State),
			"transactionId": nullable(snapshot.Transaction.TransactionID),
		},
	}
}

func validateSnapshot(snapshot inspectionSnapshot) error {
	if _, err := admit.SHA256Ref(snapshot.Transaction.Epoch, "project status transaction epoch"); err != nil {
		return err
	}
	switch snapshot.Transaction.State {
	case TransactionClean, TransactionInvalid:
		if snapshot.Transaction.TransactionID != "" {
			return fmt.Errorf("project status transaction identity is invalid for its state")
		}
	case TransactionRecoverable:
		if _, err := admit.SHA256Ref(snapshot.Transaction.TransactionID, "project status recoverable transaction"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("project status transaction state is invalid")
	}
	if snapshot.Transaction.State != TransactionClean {
		if snapshot.Manifest.State != ManifestAbsent || snapshot.ProjectID != "" || len(snapshot.Children) != 0 || snapshot.ClosureState != ClosureNotEvaluated {
			return fmt.Errorf("project status transaction-first snapshot contains later observations")
		}
		return nil
	}
	switch snapshot.Manifest.State {
	case ManifestAbsent:
		if snapshot.Manifest.ContentDigest != "" || snapshot.Manifest.ManifestID != "" || snapshot.ProjectID != "" || len(snapshot.Children) != 0 || snapshot.ClosureState != ClosureNotEvaluated {
			return fmt.Errorf("project status absent manifest observation is inconsistent")
		}
	case ManifestInvalid:
		if snapshot.Manifest.ContentDigest != "" {
			if _, err := admit.SHA256Ref(snapshot.Manifest.ContentDigest, "project status invalid manifest digest"); err != nil {
				return err
			}
		}
		if snapshot.Manifest.ManifestID != "" || snapshot.ProjectID != "" || len(snapshot.Children) != 0 || snapshot.ClosureState != ClosureNotEvaluated {
			return fmt.Errorf("project status invalid manifest observation is inconsistent")
		}
	case ManifestAdmitted:
		if _, err := admit.SHA256Ref(snapshot.Manifest.ContentDigest, "project status manifest content digest"); err != nil {
			return err
		}
		if _, err := admit.SHA256Ref(snapshot.Manifest.ManifestID, "project status manifest identity"); err != nil {
			return err
		}
		if _, err := admit.RuleID(snapshot.ProjectID, "project status project identity"); err != nil {
			return err
		}
		if len(snapshot.Children) < 3 {
			return fmt.Errorf("project status admitted manifest must observe every routed child")
		}
		allAdmitted := true
		for _, child := range snapshot.Children {
			if _, err := admit.RuleID(child.ArtifactKind, "project status child artifact kind"); err != nil {
				return err
			}
			if _, err := admit.SHA256Ref(child.ExpectedDigest, "project status child expected digest"); err != nil {
				return err
			}
			switch child.State {
			case ChildMissing:
				if child.ObservedDigest != "" {
					return fmt.Errorf("project status missing child has an observed digest")
				}
			case ChildDigestMismatch:
				if _, err := admit.SHA256Ref(child.ObservedDigest, "project status child observed digest"); err != nil {
					return err
				}
				if child.ObservedDigest == child.ExpectedDigest {
					return fmt.Errorf("project status mismatched child digests are equal")
				}
			case ChildInvalid:
				if child.ObservedDigest != "" {
					if _, err := admit.SHA256Ref(child.ObservedDigest, "project status invalid child digest"); err != nil {
						return err
					}
					if child.ObservedDigest != child.ExpectedDigest {
						return fmt.Errorf("project status invalid child bypassed digest currentness")
					}
				}
			case ChildAdmitted:
				if child.ObservedDigest != child.ExpectedDigest {
					return fmt.Errorf("project status admitted child digest does not match its route")
				}
			default:
				return fmt.Errorf("project status child state is invalid")
			}
			allAdmitted = allAdmitted && child.State == ChildAdmitted
		}
		if allAdmitted {
			if snapshot.ClosureState != ClosureAdmitted && snapshot.ClosureState != ClosureInvalid {
				return fmt.Errorf("project status closure state was not evaluated")
			}
		} else if snapshot.ClosureState != ClosureNotEvaluated {
			return fmt.Errorf("project status closure was evaluated before child admission completed")
		}
	default:
		return fmt.Errorf("project status manifest state is invalid")
	}
	return nil
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func snapshotID(snapshot inspectionSnapshot) (string, error) {
	return digest.StableJSONSHA256Ref(snapshot.identityValue())
}
