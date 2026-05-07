package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tiny-url/config"
	"tiny-url/handlers"
	"tiny-url/middleware"
	"tiny-url/services"
)

func main() {
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

	denyList, err := loadDenyList(cfg)
	if err != nil {
		fatalf("deny-list: %v", err)
	}
	if denyList != nil {
		slog.Info("deny-list active", "hosts", denyList.Size())
	}

	// IP-hash salt is initialised even when LogClickIP is off — installing a
	// salt is cheap, and tests / future env updates that flip the flag don't
	// need to re-bootstrap.
	services.SetClickSalt(cfg.ClickIPSalt)

	staticAssets, err := handlers.NewStaticAssets(staticDirFS())
	if err != nil {
		fatalf("static assets: %v", err)
	}

	shortenHandler := handlers.NewShortenHandler(store, cfg.BaseURL, cfg.MaxExpirationMinutes, cfg.MaxBodyBytes, denyList)
	redirectHandler := handlers.NewRedirectHandler(store, handlers.RedirectConfig{
		DenyList:   denyList,
		TrustProxy: cfg.TrustProxy,
		LogIP:      cfg.LogClickIP,
	})
	analyticsHandler := handlers.NewAnalyticsHandler(store)
	clicksHandler := handlers.NewClicksHandler(store, 200)
	deleteHandler := handlers.NewDeleteHandler(store)
	patchHandler := handlers.NewPatchHandler(store, cfg.MaxExpirationMinutes, cfg.MaxBodyBytes, denyList)
	qrHandler := handlers.NewQRHandler(store, cfg.BaseURL)
	healthHandler := handlers.NewHealthHandler(storageBackendName(cfg.StorageBackend))
	readyHandler := handlers.NewReadyHandler(store, 2*time.Second)

	writeLimiter := middleware.NewLimiter(ctx, cfg.WriteRatePerMin, time.Minute, cfg.TrustProxy)
	readLimiter := middleware.NewLimiter(ctx, cfg.ReadRatePerMin, time.Minute, cfg.TrustProxy)

	// appMux: rate-limited application routes. PATCH and DELETE are both
	// gated by the per-URL admin token, which a cross-origin page cannot
	// read out of localStorage on this origin — the bearer token is the
	// real CSRF defence. The X-Requested-With check stays on POST /api/shorten
	// (which has no auth) and is intentionally NOT applied to PATCH/DELETE
	// for consistency.
	appMux := http.NewServeMux()
	appMux.Handle("POST /api/shorten",
		writeLimiter.Middleware(middleware.RequireXRequestedWith(shortenHandler)))
	appMux.Handle("DELETE /api/url/{code}",
		writeLimiter.Middleware(deleteHandler))
	appMux.Handle("PATCH /api/url/{code}",
		writeLimiter.Middleware(patchHandler))
	appMux.Handle("GET /api/analytics/{code}", analyticsHandler)
	appMux.Handle("GET /api/analytics/{code}/clicks", clicksHandler)
	appMux.Handle("GET /api/qr/{code}", qrHandler)
	appMux.Handle("GET /{code}", redirectHandler)
	appMux.Handle("GET /static/", staticAssets.FileServer())
	appMux.HandleFunc("GET /", staticAssets.ServeIndex)

	// outerMux: probes are mounted OUTSIDE the read rate-limiter so a busy
	// Kubernetes liveness/readiness loop can't deplete the bucket and start
	// 429-ing real traffic. /favicon.ico likewise stops falling through to
	// the redirect handler and counting toward the budget.
	outerMux := http.NewServeMux()
	outerMux.Handle("GET /healthz", healthHandler)
	outerMux.Handle("GET /readyz", readyHandler)
	outerMux.Handle("GET /metrics", middleware.GatedMetricsHandler(cfg.MetricsToken))
	if cfg.MetricsToken != "" {
		slog.Info("metrics endpoint requires bearer token (METRICS_TOKEN set)")
	}
	outerMux.Handle("GET /favicon.ico", handlers.FaviconHandler())
	outerMux.Handle("/", readLimiter.Middleware(appMux))

	// Middleware order (outermost → innermost):
	//   RequestID → Logger → Metrics → Recover → SecurityHeaders → outerMux
	//
	// RequestID first so every log/metric carries the ID. Logger and Metrics
	// wrap Recover so their wrapped responseWriters observe the 500 status
	// the recover branch sets — without that, a panicked handler would be
	// counted as 2xx and logged with status=200. SecurityHeaders sits inside
	// Recover so the standard headers still ship on the recovered 500.
	handler := middleware.RequestID(
		middleware.Logger(
			middleware.Metrics(
				middleware.Recover(
					middleware.SecurityHeaders(cfg.TLSEnabled())(outerMux),
				),
			),
		),
	)

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
	case "", "memory":
		slog.Info("storage backend", "kind", "memory", "note", "data is lost on restart")
		return services.NewMemoryStore(), nil
	default:
		return nil, fmt.Errorf("unknown STORAGE_BACKEND %q (want memory|sqlite)", cfg.StorageBackend)
	}
}
