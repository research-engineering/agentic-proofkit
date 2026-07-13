package requirementbrowser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	serverIdleTimeout       = 30 * time.Second
	serverReadHeaderTimeout = 5 * time.Second
	serverReadTimeout       = 15 * time.Second
	serverShutdownTimeout   = 5 * time.Second
	serverWriteTimeout      = 15 * time.Second
)

var ErrOneShotTerminal = errors.New("requirement browser one-shot terminal state")

type ServerHandle struct {
	Host       string
	Port       int
	SnapshotID string
	URL        string
	Handoff    <-chan map[string]any

	close    func(context.Context) error
	done     <-chan error
	terminal *terminalArbiter
}

type terminalArbiter struct {
	mu        sync.Mutex
	committed bool
	packets   chan map[string]any
}

func newTerminalArbiter() *terminalArbiter {
	return &terminalArbiter{packets: make(chan map[string]any, 1)}
}

func (arbiter *terminalArbiter) TryCommit(packet map[string]any) bool {
	arbiter.mu.Lock()
	defer arbiter.mu.Unlock()
	if arbiter.committed {
		return false
	}
	arbiter.committed = true
	arbiter.packets <- packet
	return true
}

func (handle ServerHandle) Close(ctx context.Context) error {
	if handle.close == nil {
		return nil
	}
	return handle.close(ctx)
}

func (handle ServerHandle) Done() <-chan error {
	return handle.done
}

func StartServer(raw any, options Options) (ServerHandle, error) {
	if options.Host == "" {
		options.Host = defaultHost
	}
	if !options.PortSet {
		options.Port = defaultPort
	}
	if err := admitLoopbackHost(options.Host); err != nil {
		return ServerHandle{}, err
	}
	if err := admitPort(options.Port); err != nil {
		return ServerHandle{}, err
	}
	rendered, err := render(raw, options)
	if err != nil {
		return ServerHandle{}, err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(options.Host, strconv.Itoa(options.Port)))
	if err != nil {
		return ServerHandle{}, err
	}
	actualPort, err := listenerPort(listener)
	if err != nil {
		_ = listener.Close()
		return ServerHandle{}, err
	}
	expectedAuthority := net.JoinHostPort(options.Host, strconv.Itoa(actualPort))
	capability, err := browserCapability()
	if err != nil {
		_ = listener.Close()
		return ServerHandle{}, err
	}
	if rendered.workspace != nil {
		marker := `content="` + workspaceCapabilityPlaceholder + `"`
		if strings.Count(rendered.html, marker) != 1 {
			_ = listener.Close()
			return ServerHandle{}, fmt.Errorf("requirement browser capability marker must occur exactly once")
		}
		rendered.html = strings.Replace(rendered.html, marker, `content="`+capability+`"`, 1)
	}
	terminal := newTerminalArbiter()
	server := &http.Server{
		Handler:           browserHandler(options.View, rendered, expectedAuthority, capability, options.SessionMode == "one-shot-question", terminal),
		IdleTimeout:       serverIdleTimeout,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
	}
	done := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			done <- err
			return
		}
		done <- nil
	}()
	return ServerHandle{
		Host:       options.Host,
		Port:       actualPort,
		SnapshotID: workspaceSnapshotID(rendered.workspace),
		URL:        browserURL(options.Host, actualPort),
		Handoff:    terminal.packets,
		close: func(ctx context.Context) error {
			shutdownErr := server.Shutdown(ctx)
			if shutdownErr == nil {
				return nil
			}
			return errors.Join(shutdownErr, server.Close())
		},
		done:     done,
		terminal: terminal,
	}, nil
}

func Serve(ctx context.Context, raw any, options Options, stdout io.Writer) error {
	handle, err := StartServer(raw, options)
	if err != nil {
		return err
	}
	defer func() { _ = closeHandle(handle) }()
	if options.Open {
		if err := openBrowser(ctx, handle.URL); err != nil {
			return err
		}
	}
	if options.SessionMode == "one-shot-question" {
		timeout := options.SessionTimeout
		if timeout == 0 {
			timeout = 30 * time.Minute
		}
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case packet := <-handle.Handoff:
			return writeOneShotPacket(stdout, packet, packet["state"] != "submitted")
		case <-timer.C:
			return commitOrReadTerminal(handle, terminalPacket("expired", handle), stdout)
		case <-ctx.Done():
			return commitOrReadTerminal(handle, terminalPacket("cancelled", handle), stdout)
		case err := <-handle.Done():
			return err
		}
	}
	if _, err := fmt.Fprintf(stdout, "Proofkit requirement browser: %s\n", handle.URL); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		closeErr := closeHandle(handle)
		waitCtx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()
		return errors.Join(closeErr, waitServerDone(waitCtx, handle))
	case err := <-handle.Done():
		return err
	}
}

func commitOrReadTerminal(handle ServerHandle, candidate map[string]any, stdout io.Writer) error {
	if handle.terminal.TryCommit(candidate) {
		return writeOneShotPacket(stdout, candidate, true)
	}
	winner := <-handle.Handoff
	return writeOneShotPacket(stdout, winner, winner["state"] != "submitted")
}

func terminalPacket(state string, handle ServerHandle) map[string]any {
	packet := map[string]any{
		"handoffKind":   "proofkit.requirement-browser-question",
		"nonClaims":     admit.StringSliceToAny(serverNonClaims),
		"schemaVersion": json.Number("1"),
		"state":         state,
	}
	if handle.SnapshotID != "" {
		packet["snapshotRefs"] = []any{map[string]any{"role": "current", "snapshotId": handle.SnapshotID}}
	}
	return packet
}

func workspaceSnapshotID(session *workspaceSession) string {
	if session == nil {
		return ""
	}
	return session.SnapshotID
}

func writeOneShotPacket(stdout io.Writer, packet map[string]any, unsuccessful bool) error {
	output, err := stablejson.MarshalLayout(packet, stablejson.LayoutCompact)
	if err != nil {
		return err
	}
	if _, err := stdout.Write(output); err != nil {
		return err
	}
	if unsuccessful {
		return ErrOneShotTerminal
	}
	return nil
}

func writeBody(response http.ResponseWriter, method string, body []byte) {
	if method == http.MethodHead {
		return
	}
	_, _ = response.Write(body)
}

func listenerPort(listener net.Listener) (int, error) {
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("requirement browser server did not expose a TCP address")
	}
	return address.Port, nil
}

func closeHandle(handle ServerHandle) error {
	ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
	defer cancel()
	return handle.Close(ctx)
}

func waitServerDone(ctx context.Context, handle ServerHandle) error {
	select {
	case err := <-handle.Done():
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func openBrowser(ctx context.Context, url string) error {
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command = "open"
		args = []string{url}
	case "windows":
		command = "cmd"
		args = []string{"/c", "start", "", url}
	default:
		command = "xdg-open"
		args = []string{url}
	}
	process := exec.CommandContext(ctx, command, args...)
	if err := process.Start(); err != nil {
		return fmt.Errorf("open browser: %w", err)
	}
	if err := process.Process.Release(); err != nil {
		return fmt.Errorf("open browser: release process: %w", err)
	}
	return nil
}
