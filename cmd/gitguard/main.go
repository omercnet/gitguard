// Package main provides the entrypoint for the GitGuard GitHub App.
package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/omercnet/gitguard/internal/app"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
)

var version = "dev" // changed in build process

var UserAgent = "gitguard/" + version // User agent for GitHub API requests.

const (
	// GitHub API endpoints.
	GitHubAPIURL     = "https://api.github.com/"
	GitHubGraphQLURL = "https://api.github.com/graphql"

	// Environment variable names.
	LogLevelEnv  = "LOG_LEVEL"
	LogPrettyEnv = "LOG_PRETTY"

	// Default values.
	DefaultLogLevel = "info"
	ShutdownTimeout = 10 * time.Second
	ClientTimeout   = 30 * time.Second
)

var logLevels = map[string]zerolog.Level{
	"trace":   zerolog.TraceLevel,
	"debug":   zerolog.DebugLevel,
	"info":    zerolog.InfoLevel,
	"warn":    zerolog.WarnLevel,
	"warning": zerolog.WarnLevel,
	"error":   zerolog.ErrorLevel,
	"fatal":   zerolog.FatalLevel,
	"panic":   zerolog.PanicLevel,
}

// parseLogLevel converts a log level string to zerolog.Level.
func parseLogLevel(level string) zerolog.Level {
	if lvl, exists := logLevels[strings.ToLower(level)]; exists {
		return lvl
	}
	return zerolog.InfoLevel // Default to info level
}

func main() {
	logger := setupLogger()

	cfg, err := app.LoadConfig()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to load config")
	}

	logConfigInfo(logger, cfg)

	server := setupServer(cfg, logger)

	runServerWithGracefulShutdown(server, logger, cfg.Server.Port)
}

// setupLogger initializes the logger with the configured log level.
func setupLogger() zerolog.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logLevel := parseLogLevel(os.Getenv(LogLevelEnv))

	var output io.Writer = os.Stdout
	if os.Getenv(LogPrettyEnv) != "" {
		output = &zerolog.ConsoleWriter{Out: os.Stderr}
	}
	logger := zerolog.New(output).With().Timestamp().Logger().Level(logLevel)

	logger.Info().Str("log_level", logLevel.String()).Str("version", version).Msg("GitGuard starting up")

	return logger
}

// logConfigInfo logs the loaded configuration details.
func logConfigInfo(logger zerolog.Logger, cfg *app.Config) {
	logger.Info().Msg("Configuration loaded successfully")

	logger.Debug().
		Int("server_port", cfg.Server.Port).
		Int64("github_app_id", cfg.Github.AppID).
		Bool("webhook_secret_configured", cfg.Github.WebhookSecret != "").
		Bool("private_key_configured", cfg.Github.PrivateKey != "").
		Msg("Configuration details")
}

// setupServer creates and configures the server with all handlers.
func setupServer(cfg *app.Config, logger zerolog.Logger) *app.Server {
	// Create GitHub app client creator with proper configuration
	cc := githubapp.NewClientCreator(
		GitHubAPIURL,
		GitHubGraphQLURL,
		cfg.Github.AppID,
		[]byte(cfg.Github.PrivateKey),
		githubapp.WithClientCaching(true, nil),
		githubapp.WithClientUserAgent(UserAgent),
		githubapp.WithClientTimeout(ClientTimeout),
		githubapp.WithClientMiddleware(
			githubapp.ClientLogging(zerolog.DebugLevel),
		),
	)

	// Create commit handler and server
	commitHandler := app.NewCommitHandler(cc)
	server := app.NewServer(cfg, logger)

	if err := server.Setup(commitHandler); err != nil {
		logger.Fatal().Err(err).Msg("Failed to setup server")
	}

	return server
}

// runServerWithGracefulShutdown starts the server and handles graceful shutdown.
func runServerWithGracefulShutdown(server *app.Server, logger zerolog.Logger, port int) {
	// Setup graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		logger.Info().Int("port", port).Msg("Starting HTTP server")
		if err := server.Start(); err != nil {
			logger.Fatal().Err(err).Msg("Server failed to start")
		}
	}()

	logger.Info().Msg("GitGuard server is ready to accept requests")

	// Wait for shutdown signal
	<-done
	logger.Info().Msg("Shutdown signal received, stopping server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	logger.Info().Msg("Server stopped gracefully")
}
