package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
)

const (
	// HTTP headers.
	GitHubEventHeader     = "X-GitHub-Event"
	GitHubDeliveryHeader  = "X-GitHub-Delivery"
	GitHubSignatureHeader = "X-Hub-Signature-256"
	ContentTypeHeader     = "Content-Type"
	UserAgentHeader       = "User-Agent"

	// HTTP endpoints.
	HealthEndpoint = "/health"
	TestEndpoint   = "/test"

	// HTTP status messages.
	StatusOK                 = "OK"
	StatusTestReceived       = "Test request received"
	StatusMissingEventHeader = "Missing X-GitHub-Event header"
	StatusMissingSignature   = "Missing X-Hub-Signature-256 header"
	StatusInvalidSignature   = "Invalid webhook signature"
	StatusInvalidPayload     = "Invalid webhook payload"
	StatusInternalError      = "Internal server error"

	// GitHub event types.
	PushEventType = "push"

	// Server timeouts.
	ReadTimeout  = 30 * time.Second
	WriteTimeout = 30 * time.Second
	IdleTimeout  = 60 * time.Second

	// Request ID generation.
	RequestIDBytes = 16

	// Secret masking.
	MinSecretLength = 6
	MaskPrefix      = "***"
	MaskSuffix      = "***"
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
	s.logger.Debug().Msg("Setting up EventDispatcher for webhook handling")

	s.logger.Trace().
		Strs("handler_events", commitHandler.Handles()).
		Str("webhook_secret_length", fmt.Sprintf("%d chars", len(s.config.Github.WebhookSecret))).
		Msg("Creating EventDispatcher with CommitHandler")

	webhookHandler := s.createEventDispatcher(commitHandler)
	s.logger.Debug().Msg("EventDispatcher created successfully")

	debugWebhookHandler := s.withWebhookDebugging(webhookHandler)

	mux := http.NewServeMux()
	loggingMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := s.logger.With().
				Str("request_id", generateRequestID()).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Logger()
			ctx := logger.WithContext(r.Context())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	mux.Handle("/", loggingMiddleware(s.withLogging(debugWebhookHandler)))
	mux.HandleFunc(HealthEndpoint, s.healthHandler)
	mux.HandleFunc(TestEndpoint, s.testHandler)

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Server.Port),
		Handler:      mux,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}

	s.logger.Info().Str("address", s.server.Addr).Msg("HTTP server configured")
	s.logger.Info().
		Str("webhook_secret_configured", s.maskSecret(s.config.Github.WebhookSecret)).
		Strs("commit_handler_events", commitHandler.Handles()).
		Int("total_handlers", 1).
		Msg("EventDispatcher configured with handlers")

	return nil
}

// withLogging wraps a handler with request logging.
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		s.logRequest(r, "incoming", 0)
		next.ServeHTTP(w, r)
		s.logRequest(r, "completed", time.Since(start))
	})
}

// logRequest logs HTTP request information.
func (s *Server) logRequest(r *http.Request, stage string, duration time.Duration) {
	event := s.logger.Trace().
		Str("stage", stage).
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Str("remote_addr", r.RemoteAddr).
		Str("user_agent", r.UserAgent())

	// Add GitHub-specific headers if present
	if githubEvent := r.Header.Get(GitHubEventHeader); githubEvent != "" {
		event = event.Str("github_event", githubEvent)
	}
	if delivery := r.Header.Get(GitHubDeliveryHeader); delivery != "" {
		event = event.Str("github_delivery", delivery)
	}
	if r.Header.Get(GitHubSignatureHeader) != "" {
		event = event.Bool("has_signature", true)
	}

	// Add duration if provided (for completed requests)
	if duration > 0 {
		event = event.Dur("duration", duration)
	}

	event.Msg("HTTP request")
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	s.logger.Info().Str("address", s.server.Addr).Msg("GitGuard server starting...")

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
	s.logger.Debug().Msg("Health check requested")

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(StatusOK)); err != nil {
		s.logger.Error().Err(err).Msg("Failed to write health response")
	}
}

// testHandler handles test requests.
func (s *Server) testHandler(w http.ResponseWriter, _ *http.Request) {
	s.logger.Debug().Msg("Test request received")

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(StatusTestReceived)); err != nil {
		s.logger.Error().Err(err).Msg("Failed to write test response")
	}
}

// Add helper for creating the event dispatcher.
func (s *Server) createEventDispatcher(commitHandler *CommitHandler) http.Handler {
	return githubapp.NewEventDispatcher(
		[]githubapp.EventHandler{commitHandler},
		s.config.Github.WebhookSecret,
		githubapp.WithErrorCallback(s.webhookErrorCallback()),
	)
}

func (s *Server) webhookErrorCallback() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		logger := zerolog.Ctx(r.Context())
		logger.Error().Err(err).Msg("❌ Error processing webhook event")
		errMsg := err.Error()
		switch {
		case strings.Contains(errMsg, "signature") || strings.Contains(errMsg, "invalid"):
			http.Error(w, StatusInvalidSignature, http.StatusUnauthorized)
		case strings.Contains(errMsg, "payload") || strings.Contains(errMsg, "parse"):
			http.Error(w, StatusInvalidPayload, http.StatusBadRequest)
		default:
			http.Error(w, StatusInternalError, http.StatusInternalServerError)
		}
	}
}

// Extracted helper for logging webhook request details.
func (s *Server) logWebhookRequestDetails(r *http.Request) {
	s.logger.Trace().
		Str("path", r.URL.Path).
		Str("content_type", r.Header.Get(ContentTypeHeader)).
		Bool("has_signature", r.Header.Get(GitHubSignatureHeader) != "").
		Str("user_agent", r.Header.Get(UserAgentHeader)).
		Int64("content_length", r.ContentLength).
		Msg("Webhook request details")
}

func (s *Server) withWebhookDebugging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logger.Debug().
			Str("method", r.Method).
			Str("github_event", r.Header.Get(GitHubEventHeader)).
			Str("github_delivery", r.Header.Get(GitHubDeliveryHeader)).
			Msg("🚀 Webhook event received")

		s.logWebhookRequestDetails(r)

		githubEvent := r.Header.Get(GitHubEventHeader)
		if githubEvent == "" {
			s.logger.Warn().Msg("❌ Missing X-GitHub-Event header")
			http.Error(w, StatusMissingEventHeader, http.StatusBadRequest)
			return
		}

		signature := r.Header.Get(GitHubSignatureHeader)
		if signature == "" {
			s.logger.Warn().Msg("❌ Missing X-Hub-Signature-256 header")
			http.Error(w, StatusMissingSignature, http.StatusUnauthorized)
			return
		}
		s.logger.Trace().Str("signature_prefix", signature[:12]+"...").Msg("🔐 Webhook signature present")

		if githubEvent != PushEventType {
			s.logger.Debug().Str("github_event", githubEvent).Msg("ℹ️  Received non-push event")
		}

		ctx := s.logger.WithContext(r.Context())
		r = r.WithContext(ctx)

		wrappedWriter := &responseWriterWrapper{ResponseWriter: w, statusCode: 200}
		s.logger.Trace().Msg("📡 Calling EventDispatcher.ServeHTTP")
		next.ServeHTTP(wrappedWriter, r)

		s.logWebhookEventCompletion(r, githubEvent, wrappedWriter.statusCode)
	})
}

func (s *Server) logWebhookEventCompletion(r *http.Request, githubEvent string, statusCode int) {
	logEvent := s.logger.Debug().
		Str("github_event", githubEvent).
		Str("github_delivery", r.Header.Get(GitHubDeliveryHeader)).
		Int("response_status", statusCode)

	switch statusCode {
	case 200:
		logEvent = logEvent.Str("result", "✅ SUCCESS - Handler executed")
	case 202:
		logEvent = logEvent.Str("result", "ℹ️  ACCEPTED - No handler matched event type")
	case 400, 401:
		logEvent = logEvent.Str("result", "❌ REJECTED - Signature validation failed")
	case 404:
		logEvent = logEvent.Str("result", "❌ NOT FOUND - Invalid endpoint")
	default:
		logEvent = logEvent.Str("result", fmt.Sprintf("⚠️  UNEXPECTED - Status %d", statusCode))
	}

	logEvent.Msg("🏁 Webhook event processed")
}

// responseWriterWrapper captures the response status code.
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriterWrapper) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// maskSecret masks a secret for logging, showing only first/last few characters.
func (s *Server) maskSecret(secret string) string {
	if len(secret) <= MinSecretLength {
		return MaskPrefix
	}
	return secret[:3] + MaskSuffix + secret[len(secret)-3:]
}

// generateRequestID creates a unique request ID for tracking purposes.
func generateRequestID() string {
	bytes := make([]byte, RequestIDBytes)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a simple hash if crypto/rand fails
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}
