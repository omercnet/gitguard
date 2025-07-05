package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Test config validation
	_, err := LoadConfig()
	// Should fail with missing env vars
	if err == nil {
		t.Error("Expected error when environment variables are missing")
	}
}

func TestLoadConfigWithEnvVars(t *testing.T) {
	// Set up environment variables for successful config
	os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
	os.Setenv("GITHUB_APP_ID", "12345")
	os.Setenv("GITHUB_PRIVATE_KEY", "test-key")
	defer func() {
		os.Unsetenv("GITHUB_WEBHOOK_SECRET")
		os.Unsetenv("GITHUB_APP_ID")
		os.Unsetenv("GITHUB_PRIVATE_KEY")
	}()

	cfg, err := LoadConfig()
	if err != nil {
		t.Errorf("Expected no error with valid env vars, got: %v", err)
	}

	if cfg.GetWebhookSecret() != "test-secret" {
		t.Errorf("Expected webhook secret 'test-secret', got %s", cfg.GetWebhookSecret())
	}

	if cfg.GetAppID() != 12345 {
		t.Errorf("Expected app ID 12345, got %d", cfg.GetAppID())
	}
}
