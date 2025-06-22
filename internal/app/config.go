// Package app provides the core application logic for GitGuard.
package app

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
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
//
//nolint:gocyclo
func LoadConfig() (*Config, error) {
	// Load .env file if it exists (for local development)
	_ = godotenv.Load() // Ignore error, .env is optional

	cfg := &Config{}

	// Check for config file first
	if _, err := os.Stat("config.yml"); err == nil {
		data, err := os.ReadFile("config.yml")
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Load webhook secret - check for file first, then environment variable
	if webhookSecretFile := os.Getenv("GITHUB_WEBHOOK_SECRET_FILE"); webhookSecretFile != "" {
		secretData, err := os.ReadFile(webhookSecretFile) // #nosec G304 -- File path is controlled by env var for config
		if err != nil {
			return nil, fmt.Errorf("failed to read webhook secret file %s: %w", webhookSecretFile, err)
		}
		cfg.Github.WebhookSecret = string(secretData)
	} else if secret := os.Getenv("GITHUB_WEBHOOK_SECRET"); secret != "" {
		cfg.Github.WebhookSecret = secret
	}

	if appID := os.Getenv("GITHUB_APP_ID"); appID != "" {
		cfg.Github.AppID = parseInt64(appID)
	}

	// Load private key - check for file first, then environment variable
	if privateKeyFile := os.Getenv("GITHUB_PRIVATE_KEY_FILE"); privateKeyFile != "" {
		// Load private key from file
		keyData, err := os.ReadFile(privateKeyFile) // #nosec G304 -- File path is controlled by env var for config
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file %s: %w", privateKeyFile, err)
		}
		cfg.Github.PrivateKey = string(keyData)
	} else if key := os.Getenv("GITHUB_PRIVATE_KEY"); key != "" {
		// Fall back to environment variable
		cfg.Github.PrivateKey = key
	}

	if port := os.Getenv("PORT"); port != "" {
		cfg.Server.Port = parseInt(port)
	}

	// Validate required fields
	if cfg.Github.WebhookSecret == "" {
		return nil, fmt.Errorf("GITHUB_WEBHOOK_SECRET is required")
	}
	if cfg.Github.AppID == 0 {
		return nil, fmt.Errorf("GITHUB_APP_ID is required")
	}
	if cfg.Github.PrivateKey == "" {
		return nil, fmt.Errorf("GITHUB_PRIVATE_KEY or GITHUB_PRIVATE_KEY_FILE is required")
	}

	// Set default port if not configured
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}

	return cfg, nil
}

// parseInt64 converts string to int64.
func parseInt64(s string) int64 {
	if s == "" {
		return 0
	}
	result, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return result
}

// parseInt converts string to int.
func parseInt(s string) int {
	if s == "" {
		return 0
	}
	result, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return result
}
