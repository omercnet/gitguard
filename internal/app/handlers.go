package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-github/v72/github"
	"github.com/omercnet/gitguard/internal/gitleaks"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
)

// GitHubClientWrapper wraps a github.Client to implement the gitleaks.GitHubClient interface.
type GitHubClientWrapper struct {
	client *github.Client
}

// CompareCommits implements the gitleaks.GitHubClient interface.
func (w *GitHubClientWrapper) CompareCommits(
	ctx context.Context,
	owner, repo, base, head string,
	opts *github.ListOptions,
) (*github.CommitsComparison, *github.Response, error) {
	result, resp, err := w.client.Repositories.CompareCommits(ctx, owner, repo, base, head, opts)
	if err != nil {
		return nil, resp, fmt.Errorf("failed to compare commits: %w", err)
	}
	return result, resp, nil
}

// GetContents implements the gitleaks.GitHubClient interface.
func (w *GitHubClientWrapper) GetContents(
	ctx context.Context,
	owner, repo, path string,
	opts *github.RepositoryContentGetOptions,
) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error) {
	fileContent, directoryContent, resp, err := w.client.Repositories.GetContents(ctx, owner, repo, path, opts)
	if err != nil {
		return nil, nil, resp, fmt.Errorf("failed to get contents: %w", err)
	}
	return fileContent, directoryContent, resp, nil
}

// CommitHandler handles push events to scan commits for secrets.
type CommitHandler struct {
	githubapp.ClientCreator
	detector *gitleaks.Detector
}

// NewCommitHandler creates a new commit handler with gitleaks detector.
func NewCommitHandler(cc githubapp.ClientCreator) *CommitHandler {
	return &CommitHandler{
		ClientCreator: cc,
		detector:      gitleaks.NewDetector(),
	}
}

// Handles returns the list of event types this handler can process.
func (h *CommitHandler) Handles() []string {
	return []string{"push"}
}

// Handle processes push events to scan commits for secrets.
func (h *CommitHandler) Handle(ctx context.Context, eventType, deliveryID string, payload []byte) error {
	var event github.PushEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf("failed to unmarshal push event: %w", err)
	}

	logger := zerolog.Ctx(ctx).With().
		Str("event_type", eventType).
		Str("delivery_id", deliveryID).
		Str("ref", event.GetRef()).
		Str("repo", event.GetRepo().GetFullName()).
		Int("commit_count", len(event.Commits)).
		Logger()

	logger.Info().Msg("Processing push event for commit scanning")

	// Skip if no commits (e.g., branch deletion)
	if len(event.Commits) == 0 {
		logger.Debug().Msg("No commits in push event")
		return nil
	}

	// Skip non-branch pushes (tags, etc.)
	if !strings.HasPrefix(event.GetRef(), "refs/heads/") {
		logger.Debug().Msg("Ignoring non-branch push")
		return nil
	}

	installationID := githubapp.GetInstallationIDFromEvent(&event)
	client, err := h.NewInstallationClient(installationID)
	if err != nil {
		return fmt.Errorf("failed to create installation client: %w", err)
	}

	// Scan each commit in the push
	for _, headCommit := range event.Commits {
		if headCommit.GetSHA() == "" {
			continue
		}

		logger := logger.With().Str("commit_sha", headCommit.GetSHA()).Logger()

		// Convert HeadCommit to regular Commit struct
		commit := github.Commit{
			SHA: headCommit.SHA,
		}

		err := h.scanCommit(ctx, client, &event, commit, logger)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to scan commit")
			// Continue with other commits even if one fails
		}
	}

	return nil
}

//nolint:funlen // This is a long function, but it is necessary to scan the commit for secrets.
func (h *CommitHandler) scanCommit(ctx context.Context, client *github.Client, event *github.PushEvent,
	commit github.Commit, logger zerolog.Logger,
) error {
	owner := event.GetRepo().GetOwner().GetLogin()
	repo := event.GetRepo().GetName()
	sha := commit.GetSHA()

	// Create initial check run
	checkRun := &github.CreateCheckRunOptions{
		Name:    "gitguard-secret-scan",
		HeadSHA: sha,
		Status:  github.Ptr("in_progress"),
		Output: &github.CheckRunOutput{
			Title:   github.Ptr("GitGuard Secret Scan"),
			Summary: github.Ptr("🔍 Scanning commit for secrets and sensitive information..."),
		},
	}

	createdCheck, _, err := client.Checks.CreateCheckRun(ctx, owner, repo, *checkRun)
	if err != nil {
		return fmt.Errorf("failed to create check run: %w", err)
	}

	logger.Info().Int64("check_run_id", createdCheck.GetID()).Msg("Created check run")

	// Wrap the GitHub client to implement the gitleaks.GitHubClient interface
	wrappedClient := &GitHubClientWrapper{client: client}

	// Scan the commit for secrets using gitleaks detector
	scanResult, err := h.detector.ScanCommit(ctx, wrappedClient, owner, repo, sha, logger)
	if err != nil {
		// Update check run with error
		updateCheck := &github.UpdateCheckRunOptions{
			Name:       "gitguard-secret-scan",
			Status:     github.Ptr("completed"),
			Conclusion: github.Ptr("failure"),
			Output: &github.CheckRunOutput{
				Title:   github.Ptr("GitGuard Secret Scan - Error"),
				Summary: github.Ptr("❌ Failed to scan commit for secrets. Please try again."),
			},
		}
		_, _, updateErr := client.Checks.UpdateCheckRun(ctx, owner, repo, createdCheck.GetID(), *updateCheck)
		if updateErr != nil {
			logger.Error().Err(updateErr).Msg("Failed to update check run with error")
		}
		return fmt.Errorf("failed to scan commit with gitleaks: %w", err)
	}

	// Update check run with results
	conclusion := "success"
	title := "GitGuard Secret Scan - Clean"
	summary := "✅ No secrets or sensitive information detected in this commit."

	if scanResult.HasLeaks {
		conclusion = "failure"
		title = "GitGuard Secret Scan - Secrets Detected"
		summary = fmt.Sprintf("🚨 **%d secret(s) detected** in this commit. Please review and remove "+
			"sensitive information.", scanResult.LeakCount)

		if len(scanResult.LeakSummary) > 0 {
			summary += "\n\n**Types of secrets found:**\n" + strings.Join(scanResult.LeakSummary, "\n")
		}
	}

	updateCheck := &github.UpdateCheckRunOptions{
		Name:        "gitguard-secret-scan",
		Status:      github.Ptr("completed"),
		Conclusion:  github.Ptr(conclusion),
		CompletedAt: &github.Timestamp{Time: time.Now()},
		Output: &github.CheckRunOutput{
			Title:   github.Ptr(title),
			Summary: github.Ptr(summary),
		},
	}

	_, _, err = client.Checks.UpdateCheckRun(ctx, owner, repo, createdCheck.GetID(), *updateCheck)
	if err != nil {
		return fmt.Errorf("failed to update check run: %w", err)
	}

	logger.Info().
		Bool("has_leaks", scanResult.HasLeaks).
		Int("leak_count", scanResult.LeakCount).
		Msg("Commit scan completed")

	return nil
}
