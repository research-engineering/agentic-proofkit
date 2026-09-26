package app

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTransactionSignalScopeCloseJoins(t *testing.T) {
	for _, when := range []string{"normal", "already-canceled", "parent-canceled"} {
		t.Run(when, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			if when == "already-canceled" {
				cancel()
			}
			scope := newTransactionSignalScope(parent)
			if when == "parent-canceled" {
				cancel()
			}
			if when != "normal" {
				select {
				case <-scope.restored:
				case <-time.After(5 * time.Second):
					t.Fatal("parent cancellation did not restore signal handling")
				}
			}
			closed := make(chan struct{})
			go func() {
				scope.Close()
				scope.Close()
				close(closed)
			}()
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("scope close failed to cancel and join its waiter")
			}
			select {
			case <-scope.restored:
			default:
				t.Fatal("Close returned without joining restoration")
			}
			if !errors.Is(scope.Err(), context.Canceled) {
				t.Fatal("Close did not cancel the scope context")
			}
			if when == "normal" && parent.Err() != nil {
				t.Fatal("scope close canceled its caller")
			}
		})
	}
}
