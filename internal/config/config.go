package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

const (
	// Environment variable names.
	GitHubWebhookSecretFileEnv = "GITHUB_WEBHOOK_SECRET_FILE" // #nosec G101 -- This is an env var name, not a secret
	GitHubWebhookSecretEnv     = "GITHUB_WEBHOOK_SECRET"      // #nosec G101 -- This is an env var name, not a secret
	GitHubPrivateKeyFileEnv    = "GITHUB_PRIVATE_KEY_FILE"    // #nosec G101 -- This is an env var name, not a secret
	GitHubPrivateKeyEnv        = "GITHUB_PRIVATE_KEY"         // #nosec G101 -- This is an env var name, not a secret
	GitHubAppIDEnv             = "GITHUB_APP_ID"
	PortEnv                    = "PORT"

	// Default values.
	DefaultGitHubAPIURL     = "https://api.github.com/"
	DefaultGitHubGraphQLURL = "https://api.github.com/graphql"
	DefaultPort             = 8080

	// Error messages.
	ErrWebhookSecretRequired = "GITHUB_WEBHOOK_SECRET is required" // #nosec G101 -- This is an error message, not a secret
	ErrAppIDRequired         = "GITHUB_APP_ID is required"
	ErrPrivateKeyRequired    = "either GITHUB_PRIVATE_KEY or GITHUB_PRIVATE_KEY_FILE is required"
)

// Config holds the application configuration.
type Config struct {
	Github struct {
		WebhookSecret string `yaml:"webhook_secret"`
		AppID         int64  `yaml:"app_id"`
		PrivateKey    string `yaml:"private_key"`
		APIURL        string `yaml:"api_url"`
		GraphQLURL    string `yaml:"graphql_url"`
	} `yaml:"github"`
	Server struct {
		Port int `yaml:"port"`
	} `yaml:"server"`
}

// Simple config getters for backward compatibility.
func (c *Config) GetPort() int {
	return c.Server.Port
}

func (c *Config) GetWebhookSecret() string {
	return c.Github.WebhookSecret
}

func (c *Config) GetAppID() int64 {
	return c.Github.AppID
}

func (c *Config) GetPrivateKey() string {
	return c.Github.PrivateKey
}

func (c *Config) GetAPIURL() string {
	return c.Github.APIURL
}

func (c *Config) GetGraphQLURL() string {
	return c.Github.GraphQLURL
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}

	// Set defaults
	cfg.Github.APIURL = DefaultGitHubAPIURL
	cfg.Github.GraphQLURL = DefaultGitHubGraphQLURL
	cfg.Server.Port = DefaultPort

	// Override with environment variables
	if secret, err := getSecret(GitHubWebhookSecretFileEnv, GitHubWebhookSecretEnv); err == nil && secret != "" {
		cfg.Github.WebhookSecret = secret
	}
	if key, err := getSecret(GitHubPrivateKeyFileEnv, GitHubPrivateKeyEnv); err == nil && key != "" {
		cfg.Github.PrivateKey = key
	}
	if appID := os.Getenv(GitHubAppIDEnv); appID != "" {
		if id, err := strconv.ParseInt(appID, 10, 64); err == nil {
			cfg.Github.AppID = id
		}
	}
	if port := os.Getenv(PortEnv); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			cfg.Server.Port = p
		}
	}

	// Validate required fields
	if cfg.Github.WebhookSecret == "" {
		return nil, errors.New(ErrWebhookSecretRequired)
	}
	if cfg.Github.AppID == 0 {
		return nil, errors.New(ErrAppIDRequired)
	}
	if cfg.Github.PrivateKey == "" {
		return nil, errors.New(ErrPrivateKeyRequired)
	}

	return cfg, nil
}

func getSecret(fileEnv, directEnv string) (string, error) {
	// Check for file first
	if filePath := os.Getenv(fileEnv); filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to read secret file %s: %w", filePath, err)
		}
		return string(data), nil
	}
	// Fall back to direct environment variable
	if value := os.Getenv(directEnv); value != "" {
		return value, nil
	}
	return "", errors.New("secret not found in file or environment variable")
}
