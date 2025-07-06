package handler

import (
	"encoding/json"
	"fmt"

	"github.com/google/go-github/v72/github"
	"github.com/omercnet/gitguard/internal/constants"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// initializeDetector creates a new gitleaks detector with default configuration.
func initializeDetector() (*detect.Detector, error) {
	viperConfig := config.ViperConfig{
		Extend: config.Extend{
			UseDefault: true,
		},
	}
	cfg, err := viperConfig.Translate()
	if err != nil {
		return nil, fmt.Errorf(constants.ErrCreateGitleaksConfig, err)
	}
	return detect.NewDetector(cfg), nil
}

// parsePushEvent parses a GitHub push event from the webhook payload.
func parsePushEvent(payload []byte) (*github.PushEvent, error) {
	var event github.PushEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return nil, fmt.Errorf(constants.ErrUnmarshalPushEvent, err)
	}
	return &event, nil
}

// createGitHubClient creates a GitHub client for the given push event.
func createGitHubClient(clientCreator githubapp.ClientCreator, event *github.PushEvent) (*github.Client, error) {
	installationID := githubapp.GetInstallationIDFromEvent(event)
	client, err := clientCreator.NewInstallationClient(installationID)
	if err != nil {
		return nil, fmt.Errorf(constants.ErrCreateGitHubClient, err)
	}
	return client, nil
}
