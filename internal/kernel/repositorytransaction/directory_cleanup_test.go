package repositorytransaction

import (
	"errors"
	"strings"
	"testing"
)

func TestDirectoryAdmissionIncludesCloseOutcome(t *testing.T) {
	operationFailure := errors.New("initial admission failure")
	closeFailure := errors.New("underlying private close detail")
	for _, item := range []struct {
		name         string
		operationErr error
		closeErr     error
	}{
		{name: "success"},
		{name: "admission failure", operationErr: operationFailure},
		{name: "close failure", closeErr: closeFailure},
		{name: "both failures", operationErr: operationFailure, closeErr: closeFailure},
	} {
		t.Run(item.name, func(t *testing.T) {
			closer := &directoryCloseOutcome{err: item.closeErr}
			identity, exists, resultErr := "observed-directory", true, item.operationErr
			closeDirectoryAdmission(closer, &identity, &exists, &resultErr)
			if closer.calls != 1 {
				t.Fatalf("close calls = %d, want one", closer.calls)
			}
			if item.operationErr == nil && item.closeErr == nil {
				if identity != "observed-directory" || !exists || resultErr != nil {
					t.Fatalf("successful observation changed: %q %v %v", identity, exists, resultErr)
				}
				return
			}
			if identity != "" || exists || resultErr == nil {
				t.Fatalf("failed observation retained authority: %q %v %v", identity, exists, resultErr)
			}
			if item.operationErr != nil && !errors.Is(resultErr, operationFailure) {
				t.Fatalf("initial error lost: %v", resultErr)
			}
			if errors.Is(resultErr, ErrReadCleanup) != (item.closeErr != nil) {
				t.Fatalf("cleanup classification changed: %v", resultErr)
			}
			if strings.Contains(resultErr.Error(), closeFailure.Error()) {
				t.Fatalf("private close diagnostic was disclosed: %v", resultErr)
			}
		})
	}
}

type directoryCloseOutcome struct {
	err   error
	calls int
}

func (closer *directoryCloseOutcome) Close() error {
	closer.calls++
	return closer.err
}
