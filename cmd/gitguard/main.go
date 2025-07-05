package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/omercnet/gitguard/internal/config"
	"github.com/omercnet/gitguard/internal/handler"
	"github.com/omercnet/gitguard/internal/logging"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
)

var (
	// Version info - set by goreleaser.
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	logger := logging.SetupLogger()
	printStartupInfo(logger)
	cfg := mustLoadConfig(logger)
	server := setupServer(cfg, logger)
	runServer(server, cfg, logger)
}

func printStartupInfo(logger zerolog.Logger) {
	logger.Info().
		Str("version", version).
		Str("commit", commit).
		Str("build_date", date).
		Msg("GitGuard starting")
}

func mustLoadConfig(logger zerolog.Logger) *config.Config {
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal().Err(err).Msg("Configuration error")
	}
	logger.Info().
		Int("port", cfg.GetPort()).
		Int64("app_id", cfg.GetAppID()).
		Bool("webhook_secret_set", cfg.GetWebhookSecret() != "").
		Bool("private_key_set", cfg.GetPrivateKey() != "").
		Msg("Configuration loaded")
	return cfg
}

func setupServer(cfg *config.Config, logger zerolog.Logger) *http.Server {
	cc := githubapp.NewClientCreator(
		cfg.GetAPIURL(),
		cfg.GetGraphQLURL(),
		cfg.GetAppID(),
		[]byte(cfg.GetPrivateKey()),
		githubapp.WithClientUserAgent("gitguard/"+version),
	)

	secretHandler := &handler.SecretScanHandler{
		ClientCreator: cc,
	}
	dispatcher := githubapp.NewEventDispatcher(
		[]githubapp.EventHandler{secretHandler},
		cfg.GetWebhookSecret(),
	)

	mux := http.NewServeMux()
	mux.Handle("/", dispatcher)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		logger.Debug().Msg("Health check requested")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			logger.Error().Err(err).Msg("Failed to write health check response")
		}
	})

	server := &http.Server{
		Addr:           fmt.Sprintf(":%d", cfg.GetPort()),
		Handler:        mux,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	return server
}

func runServer(server *http.Server, cfg *config.Config, logger zerolog.Logger) {
	logger.Info().Int("port", cfg.GetPort()).Msg("GitGuard server starting")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("Server failed")
		}
		close(done)
	}()

	<-stop
	logger.Info().Msg("Shutdown signal received")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error().Err(err).Msg("Server shutdown failed")
	} else {
		logger.Info().Msg("Server shut down gracefully")
	}

	<-done
}
