package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/tools/artifactfile"
	"github.com/research-engineering/agentic-proofkit/internal/tools/installedclicontract"
	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

func minimumInstalledResult(snapshotDigest, architecture string) []byte {
	value := struct {
		SnapshotSHA256 string `json:"snapshotSHA256"`
		Architecture   string `json:"architecture"`
		Python         string `json:"python"`
		Pip            string `json:"pip"`
		CarrierCases   int    `json:"carrierCases"`
	}{snapshotDigest, architecture, minimumPython, minimumPipVersion, 6}
	content, _ := json.Marshal(value)
	return append(content, '\n')
}

func minimumPythonIdentity(content []byte, architecture string, withPip bool) error {
	type runtimeIdentity struct {
		Python         string `json:"python"`
		Machine        string `json:"machine"`
		UID            int    `json:"uid"`
		Pip            string `json:"pip"`
		Implementation string `json:"implementation"`
	}
	identity, err := minimumDecode[runtimeIdentity](content)
	if err != nil {
		return err
	}
	machine := map[string]string{"arm64": "aarch64", "amd64": "x86_64"}[architecture]
	if machine == "" || identity.Implementation != "cpython" || identity.Python != minimumPython || identity.Machine != machine || identity.UID != 65534 || (withPip && identity.Pip != minimumPipVersion) {
		return fmt.Errorf("minimum smoke requires exact CPython 3.9.0, native architecture, unprivileged UID and pinned installer")
	}
	return nil
}

func verifyMinimumInstalledPython() error {
	if runtime.GOOS != "linux" || os.Getuid() != 65534 {
		return fmt.Errorf("minimum installed mode requires the unprivileged Linux container")
	}
	const root = "/input"
	if err := os.Chdir(root); err != nil {
		return err
	}
	snapshotBytes, err := artifactfile.ReadBounded(root, "snapshot.json", 1<<20)
	if err != nil {
		return err
	}
	snapshot, err := minimumDecode[minimumSnapshot](snapshotBytes)
	if err != nil {
		return err
	}
	if snapshot.Architecture != runtime.GOARCH {
		return fmt.Errorf("minimum snapshot and runner architectures differ")
	}
	if err := minimumValidateSnapshot(snapshot); err != nil {
		return err
	}
	if err := minimumCheckSnapshot(root, snapshot); err != nil {
		return err
	}
	native, err := minimumTarget(snapshot.Architecture)
	if err != nil {
		return err
	}
	manifest, err := readPackageJSON()
	if err != nil {
		return err
	}
	if err := verifyWheelRecord(manifest, native, snapshot.Wheel); err != nil {
		return err
	}
	wheelPath := filepath.Join(root, "artifacts", "pypi", snapshot.Wheel.Filename)
	wheel, err := artifactfile.ReadBounded(root, "artifacts/pypi/"+snapshot.Wheel.Filename, maximumWheelArchiveBytes)
	if err != nil {
		return err
	}
	if err := minimumCheckWheelWrappers(wheel, root); err != nil {
		return err
	}
	pip, err := artifactfile.ReadBounded(root, minimumPipFile, 2<<20)
	if err != nil {
		return err
	}
	if err := minimumCheckDigest(pip, minimumPipSHA256); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	environment := pythonVerificationEnvironment([]string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp"}, nil)
	const identityScript = `import json, os, platform, sys; print(json.dumps(dict(python=platform.python_version(), machine=platform.machine(), uid=os.getuid(), implementation=sys.implementation.name)))`
	identity, err := minimumCommand(ctx, "/tmp", environment, "/usr/local/bin/python", "-I", "-c", identityScript)
	if err != nil {
		return err
	}
	if err := minimumPythonIdentity(identity, snapshot.Architecture, false); err != nil {
		return err
	}
	const consumer = "/tmp/consumer"
	const python = consumer + "/bin/python"
	if _, err := minimumCommand(ctx, "/tmp", environment, "/usr/local/bin/python", "-I", "-m", "venv", consumer); err != nil {
		return err
	}
	if err := installPythonWheel(python, filepath.Join(root, minimumPipFile), environment); err != nil {
		return fmt.Errorf("minimum installer bootstrap failed: %w", err)
	}
	identity, err = minimumCommand(ctx, consumer, environment, python, "-I", "-c", `import json, os, platform, pip, sys; print(json.dumps(dict(python=platform.python_version(), machine=platform.machine(), uid=os.getuid(), pip=pip.__version__, implementation=sys.implementation.name)))`)
	if err != nil {
		return err
	}
	if err := minimumPythonIdentity(identity, snapshot.Architecture, true); err != nil {
		return err
	}
	if err := installPythonWheel(python, wheelPath, environment); err != nil {
		return err
	}
	if err := os.Mkdir(consumer+"/empty-path", 0o700); err != nil {
		return err
	}
	environment = pythonVerificationEnvironment([]string{"PATH=" + consumer + "/empty-path", "HOME=/tmp"}, nil)
	renderer, err := cliexec.AdmitLauncherProfile(cliexec.ProfilePythonModule, python)
	if err != nil {
		return err
	}
	contract, err := artifactfile.ReadBounded(root, sourceCLIContractPath, installedclicontract.MaximumContractBytes)
	if err != nil {
		return err
	}
	binary, err := artifactfile.ReadBounded(root, native.BinaryPath, maximumWheelBinaryBytes)
	if err != nil {
		return err
	}
	checkInstalled := func() error {
		if _, err := verifyInstalledPythonCarrier(consumer, environment, renderer, contract, binary); err != nil {
			return err
		}
		for _, name := range []string{"__init__.py", "__main__.py", "cli.py"} {
			expected, err := artifactfile.ReadBounded(root, "python/agentic_proofkit/"+name, maximumWheelTextEntryBytes)
			if err != nil {
				return err
			}
			installed, err := readInstalledPythonPackageResource(consumer, environment, python, name, maximumWheelTextEntryBytes, "bytes")
			if err != nil || !bytes.Equal(installed, expected) {
				return fmt.Errorf("minimum installed wrapper differs from source")
			}
		}
		return nil
	}
	if err := checkInstalled(); err != nil {
		return err
	}
	for _, candidate := range installedPythonWorkflowCarriers(consumer, environment, python, consumer+"/bin/agentic-proofkit") {
		if err := workflowsmoke.VerifyCarrier(ctx, func(ctx context.Context, invocation workflowsmoke.Invocation) (workflowsmoke.Result, error) {
			return workflowsmoke.RunProcess(ctx, candidate.carrier, invocation)
		}); err != nil {
			return fmt.Errorf("minimum %s: %w", candidate.label, err)
		}
	}
	if err := checkInstalled(); err != nil {
		return err
	}
	if err := minimumCheckSnapshot(root, snapshot); err != nil {
		return err
	}
	_, err = os.Stdout.Write(minimumInstalledResult(minimumHash(snapshotBytes), snapshot.Architecture))
	return err
}
