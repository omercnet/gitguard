package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
)

// Server represents the HTTP server for the GitGuard application.
type Server struct {
	config *Config
	logger zerolog.Logger
	server *http.Server
}

// NewServer creates a new server instance.
func NewServer(cfg *Config, logger zerolog.Logger) *Server {
	return &Server{
		config: cfg,
		logger: logger,
	}
}

// Setup creates the HTTP server with all handlers.
func (s *Server) Setup(commitHandler *CommitHandler) error {
	// Create webhook handler using basic event dispatcher
	webhookHandler := githubapp.NewEventDispatcher(
		[]githubapp.EventHandler{commitHandler},
		s.config.Github.WebhookSecret,
	)

	// Set up HTTP server
	mux := http.NewServeMux()
	mux.Handle("/", webhookHandler)
	mux.HandleFunc("/health", s.healthHandler)

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Server.Port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return nil
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	s.logger.Info().Int("port", s.config.Server.Port).Msg("GitGuard server starting")
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server failed to start: %w", err)
	}
	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info().Msg("Server shutting down...")
	if s.server == nil {
		return nil
	}
	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server failed to shutdown: %w", err)
	}
	return nil
}

// healthHandler handles health check requests.
func (s *Server) healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		s.logger.Error().Err(err).Msg("Failed to write health response")
	}
}
