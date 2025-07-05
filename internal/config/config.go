package config

import (
	"errors"
	"os"
	"strconv"
)

const (
	// Environment variable names
	GitHubWebhookSecretFileEnv = "GITHUB_WEBHOOK_SECRET_FILE"
	GitHubWebhookSecretEnv     = "GITHUB_WEBHOOK_SECRET"
	GitHubPrivateKeyFileEnv    = "GITHUB_PRIVATE_KEY_FILE"
	GitHubPrivateKeyEnv        = "GITHUB_PRIVATE_KEY"
	GitHubAppIDEnv             = "GITHUB_APP_ID"
	PortEnv                    = "PORT"

	// Default values
	DefaultGitHubAPIURL     = "https://api.github.com/"
	DefaultGitHubGraphQLURL = "https://api.github.com/graphql"
	DefaultPort             = 8080

	// Error messages
	ErrWebhookSecretRequired = "GITHUB_WEBHOOK_SECRET is required"
	ErrAppIDRequired         = "GITHUB_APP_ID is required"
	ErrPrivateKeyRequired    = "GITHUB_PRIVATE_KEY is required"
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

// Simple config getters for backward compatibility
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
	if secret := getSecret(GitHubWebhookSecretFileEnv, GitHubWebhookSecretEnv); secret != "" {
		cfg.Github.WebhookSecret = secret
	}
	if key := getSecret(GitHubPrivateKeyFileEnv, GitHubPrivateKeyEnv); key != "" {
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

func getSecret(fileEnv, directEnv string) string {
	// Check for file first
	if filePath := os.Getenv(fileEnv); filePath != "" {
		if data, err := os.ReadFile(filePath); err == nil {
			return string(data)
		}
	}
	// Fall back to direct environment variable
	return os.Getenv(directEnv)
}
