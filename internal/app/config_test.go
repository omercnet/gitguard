package app_test

import (
	"os"
	"testing"

	"github.com/omercnet/gitguard/internal/app"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfigWithPrivateKeyFile(t *testing.T) {
	privateKeyContent := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
AgEAAoIBAQC7VJTUt9Us8cKB
-----END PRIVATE KEY-----`

	tmpFile, err := os.CreateTemp("", "test-private-key-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(privateKeyContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	_ = tmpFile.Close()

	if err := os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_APP_ID", "123456"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_PRIVATE_KEY_FILE", tmpFile.Name()); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("GITHUB_WEBHOOK_SECRET")
		_ = os.Unsetenv("GITHUB_APP_ID")
		_ = os.Unsetenv("GITHUB_PRIVATE_KEY_FILE")
	}()

	cfg, err := app.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Github.PrivateKey != privateKeyContent {
		t.Errorf("Expected private key content to match file content, got: %s", cfg.Github.PrivateKey)
	}

	if cfg.Github.WebhookSecret != "test-secret" {
		t.Errorf("Expected webhook secret 'test-secret', got: %s", cfg.Github.WebhookSecret)
	}

	if cfg.Github.AppID != 123456 {
		t.Errorf("Expected app ID 123456, got: %d", cfg.Github.AppID)
	}
}

func TestLoadConfigWithPrivateKeyFilePrecedence(t *testing.T) {
	privateKeyFileContent := `-----BEGIN PRIVATE KEY-----
FILE_CONTENT
-----END PRIVATE KEY-----`

	tmpFile, err := os.CreateTemp("", "test-private-key-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(privateKeyFileContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	_ = tmpFile.Close()

	if err := os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_APP_ID", "123456"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_PRIVATE_KEY", "ENV_CONTENT"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_PRIVATE_KEY_FILE", tmpFile.Name()); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("GITHUB_WEBHOOK_SECRET")
		_ = os.Unsetenv("GITHUB_APP_ID")
		_ = os.Unsetenv("GITHUB_PRIVATE_KEY")
		_ = os.Unsetenv("GITHUB_PRIVATE_KEY_FILE")
	}()

	cfg, err := app.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Github.PrivateKey != privateKeyFileContent {
		t.Errorf("Expected private key content from file, got: %s", cfg.Github.PrivateKey)
	}
}

func TestLoadConfigWithMissingPrivateKeyFile(t *testing.T) {
	if err := os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_APP_ID", "123456"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_PRIVATE_KEY_FILE", "/non/existent/file.pem"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("GITHUB_WEBHOOK_SECRET")
		_ = os.Unsetenv("GITHUB_APP_ID")
		_ = os.Unsetenv("GITHUB_PRIVATE_KEY_FILE")
	}()

	_, err := app.LoadConfig()
	if err == nil {
		t.Fatal("Expected error when private key file doesn't exist")
	}

	expectedError := "failed to read private key file"
	if err.Error()[:len(expectedError)] != expectedError {
		t.Errorf("Expected error containing '%s', got: %v", expectedError, err)
	}
}

func TestLoadConfigWithWebhookSecretFile(t *testing.T) {
	webhookSecretContent := "supersecretwebhook"
	tmpFile, err := os.CreateTemp("", "test-webhook-secret-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(webhookSecretContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	_ = tmpFile.Close()

	if err := os.Setenv("GITHUB_WEBHOOK_SECRET_FILE", tmpFile.Name()); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_APP_ID", "123456"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_PRIVATE_KEY", "dummy-key"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("GITHUB_WEBHOOK_SECRET_FILE")
		_ = os.Unsetenv("GITHUB_APP_ID")
		_ = os.Unsetenv("GITHUB_PRIVATE_KEY")
	}()

	cfg, err := app.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if cfg.Github.WebhookSecret != webhookSecretContent {
		t.Errorf("Expected webhook secret from file, got: %s", cfg.Github.WebhookSecret)
	}
}

func TestLoadConfigWithWebhookSecretFilePrecedence(t *testing.T) {
	webhookSecretFileContent := "file-secret"
	tmpFile, err := os.CreateTemp("", "test-webhook-secret-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(webhookSecretFileContent); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	_ = tmpFile.Close()

	if err := os.Setenv("GITHUB_WEBHOOK_SECRET", "env-secret"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_WEBHOOK_SECRET_FILE", tmpFile.Name()); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_APP_ID", "123456"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_PRIVATE_KEY", "dummy-key"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("GITHUB_WEBHOOK_SECRET")
		_ = os.Unsetenv("GITHUB_WEBHOOK_SECRET_FILE")
		_ = os.Unsetenv("GITHUB_APP_ID")
		_ = os.Unsetenv("GITHUB_PRIVATE_KEY")
	}()

	cfg, err := app.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if cfg.Github.WebhookSecret != webhookSecretFileContent {
		t.Errorf("Expected webhook secret from file, got: %s", cfg.Github.WebhookSecret)
	}
}

func TestLoadConfigWithMissingWebhookSecretFile(t *testing.T) {
	if err := os.Setenv("GITHUB_WEBHOOK_SECRET_FILE", "/non/existent/file.txt"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_APP_ID", "123456"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_PRIVATE_KEY", "dummy-key"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("GITHUB_WEBHOOK_SECRET_FILE")
		_ = os.Unsetenv("GITHUB_APP_ID")
		_ = os.Unsetenv("GITHUB_PRIVATE_KEY")
	}()

	_, err := app.LoadConfig()
	if err == nil {
		t.Fatal("Expected error when webhook secret file doesn't exist")
	}

	expectedError := "failed to read webhook secret file"
	if err.Error()[:len(expectedError)] != expectedError {
		t.Errorf("Expected error containing '%s', got: %v", expectedError, err)
	}
}

func TestLoadConfig_MissingWebhookSecret(t *testing.T) {
	// Don't set any webhook secret
	if err := os.Setenv("GITHUB_APP_ID", "123456"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_PRIVATE_KEY", "dummy-key"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("GITHUB_APP_ID")
		_ = os.Unsetenv("GITHUB_PRIVATE_KEY")
	}()

	_, err := app.LoadConfig()
	if err == nil {
		t.Fatal("Expected error when webhook secret is missing")
	}
	assert.Contains(t, err.Error(), "GITHUB_WEBHOOK_SECRET is required")
}

func TestLoadConfig_MissingAppID(t *testing.T) {
	if err := os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_PRIVATE_KEY", "dummy-key"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("GITHUB_WEBHOOK_SECRET")
		_ = os.Unsetenv("GITHUB_PRIVATE_KEY")
	}()

	_, err := app.LoadConfig()
	if err == nil {
		t.Fatal("Expected error when app ID is missing")
	}
	assert.Contains(t, err.Error(), "GITHUB_APP_ID is required")
}

func TestLoadConfig_MissingPrivateKey(t *testing.T) {
	if err := os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_APP_ID", "123456"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("GITHUB_WEBHOOK_SECRET")
		_ = os.Unsetenv("GITHUB_APP_ID")
	}()

	_, err := app.LoadConfig()
	if err == nil {
		t.Fatal("Expected error when private key is missing")
	}
	assert.Contains(t, err.Error(), "GITHUB_PRIVATE_KEY or GITHUB_PRIVATE_KEY_FILE is required")
}

func TestLoadConfig_InvalidConfigFile(t *testing.T) {
	// Create an invalid config file
	tmpFile, err := os.CreateTemp("", "invalid-config-*.yml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString("invalid: yaml: content"); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	_ = tmpFile.Close()

	// Set required env vars
	if err := os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_APP_ID", "123456"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_PRIVATE_KEY", "dummy-key"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("GITHUB_WEBHOOK_SECRET")
		_ = os.Unsetenv("GITHUB_APP_ID")
		_ = os.Unsetenv("GITHUB_PRIVATE_KEY")
	}()

	// Rename the invalid file to config.yml
	oldName := tmpFile.Name()
	newName := "config.yml"
	if err := os.Rename(oldName, newName); err != nil {
		t.Fatalf("Failed to rename file: %v", err)
	}
	defer func() { _ = os.Remove(newName) }()

	_, err = app.LoadConfig()
	if err == nil {
		t.Fatal("Expected error when config file is invalid")
	}
	assert.Contains(t, err.Error(), "failed to parse config file")
}

func TestLoadConfig_DefaultPort(t *testing.T) {
	if err := os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_APP_ID", "123456"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_PRIVATE_KEY", "dummy-key"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("GITHUB_WEBHOOK_SECRET")
		_ = os.Unsetenv("GITHUB_APP_ID")
		_ = os.Unsetenv("GITHUB_PRIVATE_KEY")
	}()

	cfg, err := app.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Should default to port 8080
	if cfg.Server.Port != 8080 {
		t.Errorf("Expected default port 8080, got %d", cfg.Server.Port)
	}
}

func TestLoadConfig_CustomPort(t *testing.T) {
	if err := os.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_APP_ID", "123456"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("GITHUB_PRIVATE_KEY", "dummy-key"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	if err := os.Setenv("PORT", "9090"); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("GITHUB_WEBHOOK_SECRET")
		_ = os.Unsetenv("GITHUB_APP_ID")
		_ = os.Unsetenv("GITHUB_PRIVATE_KEY")
		_ = os.Unsetenv("PORT")
	}()

	cfg, err := app.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Should use custom port
	if cfg.Server.Port != 9090 {
		t.Errorf("Expected custom port 9090, got %d", cfg.Server.Port)
	}
}
