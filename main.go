package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"tiny-url/config"
	"tiny-url/services"
)

// buildSHA is set at link time via -ldflags="-X main.buildSHA=$(git rev-parse --short HEAD)"
// (see Makefile / Dockerfile). When unset (e.g. `go run`), `tiny-url
// --version` falls back to whatever runtime/debug.ReadBuildInfo can recover
// from VCS metadata.
var buildSHA = ""

// buildVersion is set at link time on tagged release builds (e.g. v1.0.0).
// Empty otherwise; ReadBuildInfo's pseudo-version is the fallback.
var buildVersion = ""

func main() {
	// Handle --version before doing any other work so it stays fast and
	// has no side effects (no log output, no env reads). Operators
	// `tiny-url --version` to confirm what's running on a host.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "--version", "-version", "-v":
			printVersion()
			return
		}
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	cfg := config.Load()

	if err := config.ValidateBaseURL(cfg.BaseURL); err != nil {
		fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := openStore(cfg)
	if err != nil {
		fatalf("store init: %v", err)
	}
	store.StartCleanupRoutine(ctx, cfg.CleanupInterval)

	handler, err := buildHandler(ctx, cfg, store)
	if err != nil {
		fatalf("handler init: %v", err)
	}

	server := &http.Server{
		Addr:         cfg.Addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		if cfg.TLSEnabled() {
			slog.Info("starting tiny-url", "scheme", "https", "addr", cfg.Addr)
			serverErr <- server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			slog.Info("starting tiny-url",
				"scheme", "http",
				"addr", cfg.Addr,
				"hint", "set TLS_CERT_FILE/TLS_KEY_FILE or front with a TLS-terminating proxy in production")
			serverErr <- server.ListenAndServe()
		}
	}()

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatalf("server: %v", err)
		}
	case <-ctx.Done():
		// SIGTERM has arrived. The load balancer / service mesh has begun
		// deregistering us but in-flight requests may still be routed for
		// a few seconds — sleep through that window so they hit the live
		// listener instead of a closed one. SHUTDOWN_DRAIN_SECS=0 disables.
		if cfg.ShutdownDrain > 0 {
			slog.Info("shutdown signal received, draining",
				"drain", cfg.ShutdownDrain.String())
			drainCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownDrain)
			<-drainCtx.Done()
			cancel()
		} else {
			slog.Info("shutdown signal received")
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful shutdown failed", "err", err)
		} else {
			slog.Info("server stopped cleanly")
		}
	}

	if err := store.Close(); err != nil {
		slog.Error("store close", "err", err)
	}
}

// fatalf logs at error level and exits 1. Used for startup-fatal errors
// where slog gives nicer output than log.Fatalf and we want a single
// codepath that's easy to grep for.
func fatalf(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

// printVersion writes one line of build metadata to stdout. Prefers the
// linker-injected buildSHA (Makefile path) and falls back to whatever
// runtime/debug can recover from go install / module-aware builds.
func printVersion() {
	sha := buildSHA
	mod := ""
	goVer := ""
	version := buildVersion
	if info, ok := debug.ReadBuildInfo(); ok {
		goVer = info.GoVersion
		if version == "" {
			version = info.Main.Version
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if sha == "" && len(s.Value) >= 7 {
					sha = s.Value[:7]
				}
			case "vcs.modified":
				if s.Value == "true" {
					mod = "+dirty"
				}
			}
		}
	}
	if sha == "" {
		sha = "unknown"
	}
	fmt.Printf("tiny-url version=%s commit=%s%s go=%s\n", or(version, "(devel)"), sha, mod, or(goVer, "unknown"))
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func storageBackendName(backend string) string {
	if backend == "" {
		return "memory"
	}
	return backend
}

// loadDenyList merges DENY_HOSTS (env CSV) and DENY_HOSTS_FILE (file path)
// into a single list. Returns nil when neither is configured so handlers
// don't pay the per-request lookup overhead.
func loadDenyList(cfg config.Config) (*services.DenyList, error) {
	envList := services.NewDenyList(cfg.DenyHosts)
	fileList, err := services.LoadDenyListFile(cfg.DenyHostsFile)
	if err != nil {
		return nil, err
	}
	return services.MergeDenyLists(envList, fileList), nil
}

func openStore(cfg config.Config) (services.Store, error) {
	switch cfg.StorageBackend {
	case "sqlite":
		slog.Info("storage backend", "kind", "sqlite", "path", cfg.SQLitePath)
		s, err := services.NewSQLiteStore(cfg.SQLitePath)
		if err != nil {
			return nil, err
		}
		if cfg.ClickRetentionDays > 0 {
			s.SetClickRetention(time.Duration(cfg.ClickRetentionDays) * 24 * time.Hour)
		}
		return s, nil
	case "postgres":
		if cfg.PostgresDSN == "" {
			return nil, fmt.Errorf("STORAGE_BACKEND=postgres but POSTGRES_DSN is not set")
		}
		slog.Info("storage backend", "kind", "postgres")
		s, err := services.NewPostgresStore(cfg.PostgresDSN)
		if err != nil {
			return nil, err
		}
		if cfg.ClickRetentionDays > 0 {
			s.SetClickRetention(time.Duration(cfg.ClickRetentionDays) * 24 * time.Hour)
		}
		return s, nil
	case "", "memory":
		slog.Info("storage backend", "kind", "memory", "note", "data is lost on restart")
		return services.NewMemoryStore(), nil
	default:
		return nil, fmt.Errorf("unknown STORAGE_BACKEND %q (want memory|sqlite|postgres)", cfg.StorageBackend)
	}
}
