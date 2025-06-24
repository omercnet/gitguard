// Package app provides the core application logic for GitGuard.
package app

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

const (
	// Environment variable names.
	GitHubWebhookSecretFileEnv = "GITHUB_WEBHOOK_SECRET_FILE" // #nosec G101
	GitHubWebhookSecretEnv     = "GITHUB_WEBHOOK_SECRET"      // #nosec G101
	GitHubPrivateKeyFileEnv    = "GITHUB_PRIVATE_KEY_FILE"
	GitHubPrivateKeyEnv        = "GITHUB_PRIVATE_KEY"
	GitHubAppIDEnv             = "GITHUB_APP_ID"
	PortEnv                    = "PORT"

	// Configuration file.
	ConfigFileName = "config.yml"

	// Default values.
	DefaultPort = 8080

	// Error messages.
	ErrWebhookSecretRequired = "GITHUB_WEBHOOK_SECRET is required" // #nosec G101
	ErrAppIDRequired         = "GITHUB_APP_ID is required"
	ErrPrivateKeyRequired    = "GITHUB_PRIVATE_KEY or GITHUB_PRIVATE_KEY_FILE is required"
	ErrReadConfigFile        = "failed to read config file: %w"
	ErrParseConfigFile       = "failed to parse config file: %w"
	ErrReadWebhookSecretFile = "failed to read webhook secret file %s: %w"
	ErrReadPrivateKeyFile    = "failed to read private key file %s: %w"
)

// Config holds the application configuration.
type Config struct {
	Github struct {
		WebhookSecret string `yaml:"webhook_secret"`
		AppID         int64  `yaml:"app_id"`
		PrivateKey    string `yaml:"private_key"`
	} `yaml:"github"`
	Server struct {
		Port int `yaml:"port"`
	} `yaml:"server"`
}

// LoadConfig loads configuration from file and environment variables.
func LoadConfig() (*Config, error) {
	// Load .env file if it exists (for local development)
	_ = godotenv.Load() // Ignore error, .env is optional

	cfg := &Config{}

	// Load from config file if exists
	if err := loadConfigFile(cfg); err != nil {
		return nil, err
	}

	// Override with environment variables
	if err := loadFromEnv(cfg); err != nil {
		return nil, err
	}

	// Validate required fields
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	// Set defaults
	setDefaults(cfg)

	return cfg, nil
}

// loadConfigFile loads configuration from config.yml if it exists.
func loadConfigFile(cfg *Config) error {
	if _, err := os.Stat(ConfigFileName); err != nil {
		// File doesn't exist, skip.
		return nil //nolint:nilerr
	}

	data, err := os.ReadFile(ConfigFileName)
	if err != nil {
		return fmt.Errorf(ErrReadConfigFile, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf(ErrParseConfigFile, err)
	}

	return nil
}

// loadFromEnv loads configuration from environment variables.
func loadFromEnv(cfg *Config) error {
	var err error

	cfg.Github.WebhookSecret, err = loadSecret(
		GitHubWebhookSecretFileEnv, GitHubWebhookSecretEnv, cfg.Github.WebhookSecret)
	if err != nil {
		return err
	}

	cfg.Github.PrivateKey, err = loadSecret(GitHubPrivateKeyFileEnv, GitHubPrivateKeyEnv, cfg.Github.PrivateKey)
	if err != nil {
		return err
	}

	if appID := os.Getenv(GitHubAppIDEnv); appID != "" {
		cfg.Github.AppID = parseint64(appID)
	}

	if port := os.Getenv(PortEnv); port != "" {
		cfg.Server.Port = parseInt(port)
	}

	return nil
}

// loadSecret loads a secret from file or environment variable (file takes precedence).
func loadSecret(fileEnv, directEnv, current string) (string, error) {
	// Check for file first
	if filePath := os.Getenv(fileEnv); filePath != "" {
		data, err := os.ReadFile(filePath) // #nosec G304 -- File path is controlled by env var for config
		if err != nil {
			// Create error message that matches test expectations
			if strings.Contains(fileEnv, "WEBHOOK_SECRET") {
				return "", fmt.Errorf(ErrReadWebhookSecretFile, filePath, err)
			}
			return "", fmt.Errorf(ErrReadPrivateKeyFile, filePath, err)
		}
		return string(data), nil
	}

	// Fall back to direct environment variable
	if value := os.Getenv(directEnv); value != "" {
		return value, nil
	}

	// Return current value if no override
	return current, nil
}

// validateConfig validates required configuration fields.
func validateConfig(cfg *Config) error {
	if cfg.Github.WebhookSecret == "" {
		return errors.New(ErrWebhookSecretRequired)
	}
	if cfg.Github.AppID == 0 {
		return errors.New(ErrAppIDRequired)
	}
	if cfg.Github.PrivateKey == "" {
		return errors.New(ErrPrivateKeyRequired)
	}
	return nil
}

// setDefaults sets default values for optional configuration.
func setDefaults(cfg *Config) {
	if cfg.Server.Port == 0 {
		cfg.Server.Port = DefaultPort
	}
}

// parseint64 converts string to int64, returns 0 on error.
func parseint64(s string) int64 {
	if s == "" {
		return 0
	}
	result, _ := strconv.ParseInt(s, 10, 64)
	return result
}

// parseInt converts string to int, returns 0 on error.
func parseInt(s string) int {
	if s == "" {
		return 0
	}
	result, _ := strconv.Atoi(s)
	return result
}
