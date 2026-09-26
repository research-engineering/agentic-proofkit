package app

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

type transactionSignalScope struct {
	context.Context
	stop     context.CancelFunc
	restored <-chan struct{}
}

func newTransactionSignalScope(parent context.Context) *transactionSignalScope {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	restored := make(chan struct{})
	go func() {
		<-ctx.Done()
		// Restore subsequent signals even if native work or output cannot return.
		stop()
		close(restored)
	}()
	return &transactionSignalScope{Context: ctx, stop: stop, restored: restored}
}

func (scope *transactionSignalScope) Close() {
	scope.stop()
	<-scope.restored
}
