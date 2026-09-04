package repositorytransaction

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	journalPath        = activeDirectory + "/journal.json"
	journalTemp        = activeDirectory + "/journal.tmp"
	readyMarker        = activeDirectory + "/ready"
	committedMarker    = activeDirectory + "/committed"
	rolledBackMarker   = activeDirectory + "/rolled-back"
	recoveryActionPath = activeDirectory + "/recovery-action.json"
	recoveryActionTemp = activeDirectory + "/recovery-action.tmp"
)

func prepareJournal(root *os.Root, plan Plan) error {
	if err := validateActivePlan(plan); err != nil {
		return err
	}
	if err := ensureDirectory(root, activeDirectory, 0o700); err != nil {
		return err
	}
	content, err := stablejson.Marshal(journalValue(plan))
	if err != nil {
		return fmt.Errorf("encode repository transaction journal")
	}
	if len(content) > MaximumJournalBytes {
		return fmt.Errorf("repository transaction journal exceeds the byte limit")
	}
	if err := writeOwnedFile(root, journalTemp, content, 0o600); err != nil {
		return err
	}
	if err := root.Rename(filepath.FromSlash(journalTemp), filepath.FromSlash(journalPath)); err != nil {
		return fmt.Errorf("publish repository transaction journal")
	}
	return syncDirectory(root, activeDirectory)
}

func publishPreparingJournal(root *os.Root) error {
	if err := root.Rename(filepath.FromSlash(journalTemp), filepath.FromSlash(journalPath)); err != nil {
		return fmt.Errorf("publish repository transaction preparing journal")
	}
	return syncDirectory(root, activeDirectory)
}

func stageObjects(root *os.Root, plan Plan) error {
	for index, operation := range plan.Operations {
		if operation.Action == ActionUnchanged {
			continue
		}
		if err := writeOwnedFile(root, afterObjectPath(index), operation.afterContent, 0o600); err != nil {
			return err
		}
		if operation.Before.Exists {
			if err := writeOwnedFile(root, beforeObjectPath(index), operation.beforeContent, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadJournal(root *os.Root) (Plan, error) {
	content, err := readOwnedFile(root, journalPath, MaximumJournalBytes)
	if err != nil {
		return Plan{}, err
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), MaximumJournalBytes)
	if err != nil {
		return Plan{}, fmt.Errorf("admit repository transaction journal")
	}
	plan, err := admitJournal(value)
	if err != nil {
		return Plan{}, err
	}
	canonical, err := stablejson.Marshal(journalValue(plan))
	if err != nil || !bytes.Equal(content, canonical) {
		return Plan{}, fmt.Errorf("repository transaction journal is not canonical")
	}
	return plan, nil
}

func loadObjects(root *os.Root, plan Plan) (Plan, error) {
	for index := range plan.Operations {
		operation := &plan.Operations[index]
		if operation.Action == ActionUnchanged {
			continue
		}
		after, err := readOwnedFile(root, afterObjectPath(index), MaximumFileBytes)
		if err != nil || !contentMatches(after, operation.After) {
			return Plan{}, fmt.Errorf("repository transaction after object is invalid")
		}
		operation.afterContent = after
		if operation.Before.Exists {
			before, err := readOwnedFile(root, beforeObjectPath(index), MaximumFileBytes)
			if err != nil || !contentMatches(before, operation.Before) {
				return Plan{}, fmt.Errorf("repository transaction before object is invalid")
			}
			operation.beforeContent = before
		}
	}
	return plan, nil
}

func contentMatches(content []byte, snapshot Snapshot) bool {
	return snapshot.Exists && int64(len(content)) == snapshot.ByteCount && digest.SHA256BytesRef(content) == snapshot.SHA256
}

func afterObjectPath(index int) string {
	return fmt.Sprintf("%s/after-%03d.bin", activeDirectory, index)
}

func beforeObjectPath(index int) string {
	return fmt.Sprintf("%s/before-%03d.bin", activeDirectory, index)
}

func markerExists(root *os.Root, marker string) (bool, error) {
	exists, err := pathExists(root, marker)
	if err != nil || !exists {
		return exists, err
	}
	info, err := root.Lstat(filepath.FromSlash(marker))
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 0 {
		return false, fmt.Errorf("repository transaction marker is invalid")
	}
	owned, err := platformOwnedByCurrentUser(info)
	if err != nil || !owned {
		return false, fmt.Errorf("repository transaction marker is not privately owned")
	}
	return true, nil
}

func writeMarker(root *os.Root, marker string) error {
	return writeAtomicOwnedFile(root, marker, marker+".tmp", nil, 0o600)
}
