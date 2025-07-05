package logging

import (
	"os"

	"github.com/rs/zerolog"
)

// SetupLogger initializes zerolog with a simple configuration.
func SetupLogger() zerolog.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Use console writer for prettier output in development
	var logger zerolog.Logger
	if os.Getenv("LOG_PRETTY") != "" {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		logger = zerolog.New(os.Stdout)
	}

	// Set log level from environment, default to info
	logLevel := zerolog.InfoLevel
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		if parsed, err := zerolog.ParseLevel(level); err == nil {
			logLevel = parsed
		}
	}

	return logger.With().Timestamp().Logger().Level(logLevel)
}

func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
