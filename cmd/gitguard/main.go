package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/omercnet/gitguard/internal/config"
	"github.com/omercnet/gitguard/internal/handler"
	"github.com/omercnet/gitguard/internal/logging"
	"github.com/palantir/go-githubapp/githubapp"
)

var (
	// Version info - set by goreleaser.
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	logger := logging.SetupLogger()
	logger.Info().
		Str("version", version).
		Str("commit", commit).
		Str("build_date", date).
		Msg("GitGuard starting")

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

	// Create GitHub App client
	cc := githubapp.NewClientCreator(
		cfg.GetAPIURL(),
		cfg.GetGraphQLURL(),
		cfg.GetAppID(),
		[]byte(cfg.GetPrivateKey()),
		githubapp.WithClientUserAgent("gitguard/"+version),
	)

	// Create handler and event dispatcher
	secretHandler := &handler.SecretScanHandler{
		ClientCreator: cc,
	}
	dispatcher := githubapp.NewEventDispatcher(
		[]githubapp.EventHandler{secretHandler},
		cfg.GetWebhookSecret(),
	)

	// Setup HTTP server
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
		Addr:    fmt.Sprintf(":%d", cfg.GetPort()),
		Handler: mux,
		// Production-ready timeouts for scale
		ReadTimeout:    30 * time.Second,  // Max time to read request
		WriteTimeout:   60 * time.Second,  // Max time to write response
		IdleTimeout:    120 * time.Second, // Max idle connection time
		MaxHeaderBytes: 1 << 20,           // 1MB max header size
	}

	logger.Info().Int("port", cfg.GetPort()).Msg("GitGuard server starting")
	if err := server.ListenAndServe(); err != nil {
		logger.Fatal().Err(err).Msg("Server failed")
	}
}
