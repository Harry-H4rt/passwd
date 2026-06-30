// Command server starts the passwd zero-knowledge sync API.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/passwd-app/server/internal/config"
	"github.com/passwd-app/server/internal/server"
	"github.com/passwd-app/server/internal/storage"
)

// openStore selects the persistence backend from config. An empty or "memory"
// PASSWD_DB uses the in-memory store (tests/ephemeral); a postgres:// URL uses
// PostgreSQL; otherwise SQLite at the given path (directories created as needed).
func openStore(cfg config.Config, logger *slog.Logger) (storage.Store, error) {
	if cfg.DBPath == "" || cfg.DBPath == "memory" {
		logger.Warn("using in-memory store (not durable); set PASSWD_DB for persistence")
		return storage.NewMemory(), nil
	}
	if strings.HasPrefix(cfg.DBPath, "postgres://") || strings.HasPrefix(cfg.DBPath, "postgresql://") {
		logger.Info("using PostgreSQL store")
		return storage.OpenPostgres(cfg.DBPath)
	}
	if dir := filepath.Dir(cfg.DBPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	logger.Info("using SQLite store", "path", cfg.DBPath)
	return storage.OpenSQLite(cfg.DBPath)
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := config.Load()

	store, err := openStore(cfg, logger)
	if err != nil {
		logger.Error("open store", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	if cfg.IsProduction() {
		if cfg.JWTSecret == "dev-only-insecure-secret-change-me" ||
			cfg.IdentifierPepper == "dev-only-insecure-pepper-change-me" {
			logger.Error("refusing to start in production with default secrets; set PASSWD_JWT_SECRET and PASSWD_IDENTIFIER_PEPPER")
			os.Exit(1)
		}
	}

	srv := server.New(cfg, store, logger)

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("passwd backend listening", "addr", cfg.Addr, "env", cfg.Environment)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
	}
}
