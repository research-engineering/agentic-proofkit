package requirementbrowser

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	serverIdleTimeout       = 30 * time.Second
	serverReadHeaderTimeout = 5 * time.Second
	serverShutdownTimeout   = 5 * time.Second
	serverWriteTimeout      = 15 * time.Second
)

type ServerHandle struct {
	Host string
	Port int
	URL  string

	close func(context.Context) error
	done  <-chan error
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
	server := &http.Server{
		Handler:           browserHandler(options.View, rendered, expectedAuthority),
		IdleTimeout:       serverIdleTimeout,
		ReadHeaderTimeout: serverReadHeaderTimeout,
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
		Host: options.Host,
		Port: actualPort,
		URL:  browserURL(options.Host, actualPort),
		close: func(ctx context.Context) error {
			shutdownErr := server.Shutdown(ctx)
			if shutdownErr == nil {
				return nil
			}
			return errors.Join(shutdownErr, server.Close())
		},
		done: done,
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

func browserHandler(view string, rendered renderedView, expectedAuthority string) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Host != expectedAuthority {
			response.Header().Set("content-type", "text/plain; charset=utf-8")
			response.WriteHeader(http.StatusForbidden)
			writeBody(response, request.Method, []byte("forbidden host\n"))
			return
		}
		expectedOrigin := "http://" + expectedAuthority
		if origin := request.Header.Get("origin"); origin != "" && origin != expectedOrigin {
			response.Header().Set("content-type", "text/plain; charset=utf-8")
			response.WriteHeader(http.StatusForbidden)
			writeBody(response, request.Method, []byte("forbidden origin\n"))
			return
		}
		method := request.Method
		if method != http.MethodGet && method != http.MethodHead {
			response.Header().Set("allow", "GET, HEAD")
			response.Header().Set("content-type", "text/plain; charset=utf-8")
			response.WriteHeader(http.StatusMethodNotAllowed)
			writeBody(response, method, []byte("method not allowed\n"))
			return
		}
		switch request.URL.Path {
		case "/", "/index.html":
			response.Header().Set("cache-control", "no-store")
			response.Header().Set("content-type", "text/html; charset=utf-8")
			response.WriteHeader(http.StatusOK)
			writeBody(response, method, []byte(rendered.html))
		case "/healthz":
			response.Header().Set("cache-control", "no-store")
			response.Header().Set("content-type", "application/json; charset=utf-8")
			response.WriteHeader(http.StatusOK)
			body, err := stablejson.Marshal(map[string]any{
				"authority": "presentation_adapter_status",
				"nonClaims": admit.StringSliceToAny(serverNonClaims),
				"state":     "ok",
				"view":      view,
				"viewKind":  rendered.viewKind,
			})
			if err != nil {
				return
			}
			writeBody(response, method, append(body, '\n'))
		default:
			response.Header().Set("content-type", "text/plain; charset=utf-8")
			response.WriteHeader(http.StatusNotFound)
			writeBody(response, method, []byte("not found\n"))
		}
	})
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
