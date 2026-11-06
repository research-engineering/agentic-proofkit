package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
)

type consumerLock struct {
	LockfileVersion int                      `json:"lockfileVersion"`
	Packages        map[string]lockedPackage `json:"packages"`
}

type lockedPackage struct {
	Bin          map[string]string `json:"bin"`
	Dependencies map[string]string `json:"dependencies"`
	InBundle     bool              `json:"inBundle"`
	Integrity    string            `json:"integrity"`
	Link         bool              `json:"link"`
	Resolved     string            `json:"resolved"`
	Version      string            `json:"version"`
}

func verifyConsumerLock(candidatePath, lockPath string) error {
	records, err := readPackRecords(candidatePath, "release candidate")
	if err != nil {
		return err
	}
	if len(records) != 1 {
		return fmt.Errorf("registry consumer requires exactly one candidate package")
	}
	file, err := os.Open(lockPath)
	if err != nil {
		return err
	}
	defer file.Close()
	lock, err := admission.DecodeTypedJSON[consumerLock](file, maxPackRecordBytes)
	if err != nil {
		return fmt.Errorf("admit registry consumer lock: %w", err)
	}
	expected := records[0]
	root, hasRoot := lock.Packages[""]
	installed, hasPackage := lock.Packages["node_modules/"+expected.Name]
	if lock.LockfileVersion != 3 || len(lock.Packages) != 2 || !hasRoot || !hasPackage ||
		len(root.Dependencies) != 1 || root.Dependencies[expected.Name] != expected.Version {
		return fmt.Errorf("registry consumer lock must resolve only the exact candidate dependency")
	}
	leaf := expected.Name[strings.LastIndexByte(expected.Name, '/')+1:]
	url := releasechannel.NPMRegistryURL + "/" + expected.Name + "/-/" + leaf + "-" + expected.Version + ".tgz"
	if installed.Link || installed.InBundle || len(installed.Dependencies) != 0 ||
		len(installed.Bin) != 1 || installed.Bin[leaf] != "dist/"+leaf || installed.Resolved != url ||
		installed.Version != expected.Version || installed.Integrity != expected.Integrity {
		return fmt.Errorf("registry consumer lock does not match the exact candidate artifact")
	}
	return nil
}
