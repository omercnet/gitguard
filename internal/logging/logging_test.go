package logging

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
)

func TestGetEnv(t *testing.T) {
	result := GetEnv("NONEXISTENT_ENV_VAR", "default")
	if result != "default" {
		t.Errorf("Expected 'default', got %s", result)
	}
}

func TestSetupLogger(t *testing.T) {
	// Test logger setup with different env vars
	originalLogLevel := os.Getenv("LOG_LEVEL")
	originalLogPretty := os.Getenv("LOG_PRETTY")

	defer func() {
		if originalLogLevel != "" {
			os.Setenv("LOG_LEVEL", originalLogLevel)
		} else {
			os.Unsetenv("LOG_LEVEL")
		}
		if originalLogPretty != "" {
			os.Setenv("LOG_PRETTY", originalLogPretty)
		} else {
			os.Unsetenv("LOG_PRETTY")
		}
	}()

	// Test with debug level
	os.Setenv("LOG_LEVEL", "debug")
	logger := SetupLogger()
	if logger.GetLevel() != zerolog.DebugLevel {
		t.Errorf("Expected debug level, got %v", logger.GetLevel())
	}

	// Test with invalid level (should default to info)
	os.Setenv("LOG_LEVEL", "invalid")
	logger = SetupLogger()
	if logger.GetLevel() != zerolog.InfoLevel {
		t.Errorf("Expected info level for invalid input, got %v", logger.GetLevel())
	}
}
