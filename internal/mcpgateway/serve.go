package mcpgateway

import (
	"context"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
)

// ServeHTTPGateway creates an MCP HTTP reverse proxy with security rules and
// runs it with graceful shutdown on SIGINT/SIGTERM. It blocks until the server
// exits. Returns an error if the server fails to start or encounters a fatal error.
func ServeHTTPGateway(upstream, listen string, engine rules.RuleEvaluator) error {
	gw, err := NewHTTPGateway(upstream, engine)
	if err != nil {
		return fmt.Errorf("gateway init: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/", gw)

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	mcpLog := logger.New("mcp.http")
	mcpLog.Info("Starting MCP HTTP gateway: listen=%s upstream=%s rules=%d",
		listen, upstream, engine.RuleCount())

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		mcpLog.Info("Shutting down MCP HTTP gateway...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		//nolint:errcheck // best-effort shutdown
		srv.Shutdown(shutdownCtx)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		gw.Close()
		return err
	}
	<-shutdownDone
	gw.Close()
	return nil
}
