// Package main provides the entrypoint for the GitGuard GitHub App.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/omercnet/gitguard/internal/app"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
)

func main() {
	// Load configuration
	cfg, err := app.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set up logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	// Create GitHub app client
	cc := githubapp.NewClientCreator(
		"", // v3BaseURL - empty for github.com
		"", // v4BaseURL - empty for github.com
		cfg.Github.AppID,
		[]byte(cfg.Github.PrivateKey),
	)

	// Create commit handler
	commitHandler := app.NewCommitHandler(cc)

	// Create and setup server
	server := app.NewServer(cfg, logger)
	if err := server.Setup(commitHandler); err != nil {
		logger.Fatal().Err(err).Msg("Failed to setup server")
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.Start(); err != nil {
			logger.Fatal().Err(err).Msg("Server failed to start")
		}
	}()

	<-done
	logger.Info().Msg("Server shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	logger.Info().Msg("Server exited")
}
