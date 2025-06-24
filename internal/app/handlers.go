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

const (
	// GitHub check run configuration.
	CheckRunName = "gitguard/secret-scan"

	// GitHub check run statuses.
	StatusInProgress = "in_progress"
	StatusCompleted  = "completed"

	// GitHub check run conclusions.
	ConclusionSuccess = "success"
	ConclusionFailure = "failure"

	// GitHub check run titles and summaries.
	CheckRunTitleInProgress = "GitGuard Secret Scan"
	CheckRunTitleError      = "GitGuard Secret Scan - Error"
	CheckRunTitleClean      = "GitGuard Secret Scan - Clean"
	CheckRunTitleSecrets    = "GitGuard Secret Scan - Secrets Detected"

	CheckRunSummaryInProgress = "🔍 Scanning commit for secrets and sensitive information..."
	CheckRunSummaryError      = "❌ Failed to scan commit for secrets. Please try again."
	CheckRunSummaryClean      = "✅ No secrets or sensitive information detected in this commit."
	CheckRunSummarySecrets    = "🚨 **%d secret(s) detected** in this commit. " +
		"Please review and remove sensitive information." // #nosec G101 -- not a credential
	CheckRunSummaryTypes = "\n\n**Types of secrets found:**\n"

	// Git references.
	BranchRefPrefix = "refs/heads/"

	// Error messages.
	ErrFailedToParsePushEvent = "failed to unmarshal push event: %w"
	ErrFailedToCreateClient   = "failed to create installation client: %w"
	ErrFailedToScanCommit     = "failed to scan commit with gitleaks: %w"
	ErrFailedToCreateCheckRun = "failed to create check run: %w"
	ErrFailedToUpdateCheckRun = "failed to update check run: %w"
)

// CommitHandler handles push events to scan commits for secrets.
type CommitHandler struct {
	githubapp.ClientCreator
	detector *gitleaks.Detector
}

// NewCommitHandler creates a new commit handler with gitleaks detector.
func NewCommitHandler(cc githubapp.ClientCreator) *CommitHandler {
	handler := &CommitHandler{
		ClientCreator: cc,
		detector:      gitleaks.NewDetector(),
	}

	return handler
}

// Handles returns the list of event types this handler can process.
func (h *CommitHandler) Handles() []string {
	return []string{PushEventType}
}

// Handle processes push events to scan commits for secrets.
func (h *CommitHandler) Handle(ctx context.Context, eventType, deliveryID string, payload []byte) error {
	// Create logger from context or fallback
	logger := zerolog.Ctx(ctx).With().
		Str("event_type", eventType).
		Str("delivery_id", deliveryID).
		Int("payload_size", len(payload)).
		Logger()

	logger.Debug().Msg("🎯 CommitHandler.Handle called - received webhook event")

	event, err := h.parsePushEvent(payload, logger)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to parse push event")
		return err
	}

	if h.shouldSkipEvent(event, logger) {
		logger.Debug().Msg("Skipping event based on filter criteria")
		return nil
	}

	logger.Info().Msg("Processing commits for secret scanning")
	return h.processCommits(ctx, event, logger)
}

// parsePushEvent parses the push event from the payload.
func (h *CommitHandler) parsePushEvent(payload []byte, logger zerolog.Logger) (*github.PushEvent, error) {
	var event github.PushEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		logger.Error().Err(err).Msg("Failed to unmarshal push event")
		return nil, fmt.Errorf(ErrFailedToParsePushEvent, err)
	}
	return &event, nil
}

// shouldSkipEvent determines if the event should be skipped.
func (h *CommitHandler) shouldSkipEvent(event *github.PushEvent, logger zerolog.Logger) bool {
	logger = logger.With().
		Str("ref", event.GetRef()).
		Str("repo", event.GetRepo().GetFullName()).
		Int("commit_count", len(event.Commits)).
		Logger()

	logger.Debug().Msg("Evaluating push event for commit scanning")

	// Skip if no commits (e.g., branch deletion)
	if len(event.Commits) == 0 {
		logger.Debug().Msg("No commits in push event")
		return true
	}

	// Skip non-branch pushes (tags, etc.)
	if !strings.HasPrefix(event.GetRef(), BranchRefPrefix) {
		logger.Debug().Msg("Ignoring non-branch push")
		return true
	}

	return false
}

// processCommits processes all commits in the push event.
func (h *CommitHandler) processCommits(ctx context.Context, event *github.PushEvent, logger zerolog.Logger) error {
	installationID := githubapp.GetInstallationIDFromEvent(event)
	client, err := h.NewInstallationClient(installationID)
	if err != nil {
		return fmt.Errorf(ErrFailedToCreateClient, err)
	}

	// Create a GitHub client wrapper for the gitleaks detector
	wrappedClient := &githubClientWrapper{client: client}

	logger.Info().
		Str("repo", event.GetRepo().GetFullName()).
		Int("commit_count", len(event.Commits)).
		Msg("Starting secret scan for commits")

	// Scan each commit in the push
	for _, headCommit := range event.Commits {
		logger.Debug().
			Str("commit_sha", headCommit.GetID()).
			Str("author", headCommit.GetAuthor().GetName()).
			Str("message", headCommit.GetMessage()).
			Msg("Processing commit for secret scan")

		commitSHA := headCommit.GetID()
		commitLogger := logger.With().Str("commit_sha", commitSHA).Logger()

		commitLogger.Debug().
			Str("author", headCommit.GetAuthor().GetName()).
			Str("message", headCommit.GetMessage()).
			Msg("Processing commit for secret scan")

		err := h.scanCommit(ctx, wrappedClient, client, event, commitSHA, commitLogger)
		if err != nil {
			commitLogger.Error().Err(err).Msg("Failed to scan commit")
			// Continue with other commits even if one fails
		}
	}

	return nil
}

// scanCommit scans a single commit for secrets.
func (h *CommitHandler) scanCommit(ctx context.Context, wrappedClient gitleaks.GitHubClient,
	client *github.Client, event *github.PushEvent, sha string, logger zerolog.Logger,
) error {
	owner := event.GetRepo().GetOwner().GetLogin()
	repo := event.GetRepo().GetName()

	// Create and manage check run
	checkRunID, err := h.createCheckRun(ctx, client, owner, repo, sha)
	if err != nil {
		return err
	}

	// Scan the commit for secrets
	scanResult, err := h.detector.ScanCommit(ctx, wrappedClient, owner, repo, sha, logger)
	if err != nil {
		h.updateCheckRunWithError(ctx, client, owner, repo, checkRunID, logger)
		return fmt.Errorf(ErrFailedToScanCommit, err)
	}

	// Log scan results at debug level
	logger.Debug().
		Str("commit_sha", sha).
		Bool("has_leaks", scanResult.HasLeaks).
		Int("leak_count", scanResult.LeakCount).
		Strs("leak_types", scanResult.LeakSummary).
		Msg("Commit scan completed")

	// Update check run with results
	return h.updateCheckRunWithResults(ctx, client, owner, repo, checkRunID, scanResult, logger)
}

// createCheckRun creates an initial check run.
func (h *CommitHandler) createCheckRun(ctx context.Context, client *github.Client, owner, repo, sha string) (
	int64, error,
) {
	logger := zerolog.Ctx(ctx).With().
		Str("owner", owner).
		Str("repo", repo).
		Str("commit_sha", sha).
		Logger()

	logger.Debug().Msg("Creating GitHub check run for secret scan")

	checkRun := &github.CreateCheckRunOptions{
		Name:    CheckRunName,
		HeadSHA: sha,
		Status:  github.Ptr(StatusInProgress),
		Output: &github.CheckRunOutput{
			Title:   github.Ptr(CheckRunTitleInProgress),
			Summary: github.Ptr(CheckRunSummaryInProgress),
		},
	}

	createdCheck, _, err := client.Checks.CreateCheckRun(ctx, owner, repo, *checkRun)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create GitHub check run")
		return 0, fmt.Errorf(ErrFailedToCreateCheckRun, err)
	}

	checkRunID := createdCheck.GetID()
	logger.Debug().
		Int64("check_run_id", checkRunID).
		Str("status", StatusInProgress).
		Msg("GitHub check run created successfully")

	return checkRunID, nil
}

// updateCheckRunWithError updates the check run with error status.
func (h *CommitHandler) updateCheckRunWithError(ctx context.Context, client *github.Client,
	owner, repo string, checkRunID int64, logger zerolog.Logger,
) {
	logger.Debug().
		Int64("check_run_id", checkRunID).
		Str("conclusion", "failure").
		Msg("Updating GitHub check run with error status")

	updateCheck := &github.UpdateCheckRunOptions{
		Name:       CheckRunName,
		Status:     github.Ptr(StatusCompleted),
		Conclusion: github.Ptr(ConclusionFailure),
		Output: &github.CheckRunOutput{
			Title:   github.Ptr(CheckRunTitleError),
			Summary: github.Ptr(CheckRunSummaryError),
		},
	}

	if _, _, err := client.Checks.UpdateCheckRun(ctx, owner, repo, checkRunID, *updateCheck); err != nil {
		logger.Error().Err(err).
			Int64("check_run_id", checkRunID).
			Msg("Failed to update GitHub check run with error status")
	} else {
		logger.Debug().
			Int64("check_run_id", checkRunID).
			Str("status", StatusCompleted).
			Str("conclusion", ConclusionFailure).
			Msg("GitHub check run updated with error status")
	}
}

// updateCheckRunWithResults updates the check run with scan results.
func (h *CommitHandler) updateCheckRunWithResults(ctx context.Context, client *github.Client,
	owner, repo string, checkRunID int64, scanResult *gitleaks.ScanResult, logger zerolog.Logger,
) error {
	conclusion, title, summary := h.buildCheckRunOutput(scanResult)

	logger.Debug().
		Int64("check_run_id", checkRunID).
		Str("conclusion", conclusion).
		Bool("has_leaks", scanResult.HasLeaks).
		Int("leak_count", scanResult.LeakCount).
		Msg("Updating GitHub check run with scan results")

	updateCheck := &github.UpdateCheckRunOptions{
		Name:        CheckRunName,
		Status:      github.Ptr(StatusCompleted),
		Conclusion:  github.Ptr(conclusion),
		CompletedAt: &github.Timestamp{Time: time.Now()},
		Output: &github.CheckRunOutput{
			Title:   github.Ptr(title),
			Summary: github.Ptr(summary),
		},
	}

	_, _, err := client.Checks.UpdateCheckRun(ctx, owner, repo, checkRunID, *updateCheck)
	if err != nil {
		logger.Error().Err(err).
			Int64("check_run_id", checkRunID).
			Msg("Failed to update GitHub check run with scan results")
		return fmt.Errorf(ErrFailedToUpdateCheckRun, err)
	}

	logger.Debug().
		Int64("check_run_id", checkRunID).
		Str("status", StatusCompleted).
		Str("conclusion", conclusion).
		Msg("GitHub check run updated with scan results")

	return nil
}

// buildCheckRunOutput builds the output for the check run based on scan results.
func (h *CommitHandler) buildCheckRunOutput(scanResult *gitleaks.ScanResult) (string, string, string) {
	if !scanResult.HasLeaks {
		return ConclusionSuccess, CheckRunTitleClean, CheckRunSummaryClean
	}

	title := CheckRunTitleSecrets
	summary := fmt.Sprintf(CheckRunSummarySecrets, scanResult.LeakCount)

	if len(scanResult.LeakSummary) > 0 {
		summary += CheckRunSummaryTypes + strings.Join(scanResult.LeakSummary, "\n")
	}

	return ConclusionFailure, title, summary
}

// githubClientWrapper wraps a github.Client to implement the gitleaks.GitHubClient interface.
type githubClientWrapper struct {
	client *github.Client
}

// CompareCommits implements the gitleaks.GitHubClient interface.
func (w *githubClientWrapper) CompareCommits(
	ctx context.Context, owner, repo, base, head string, opts *github.ListOptions,
) (*github.CommitsComparison, *github.Response, error) {
	result, resp, err := w.client.Repositories.CompareCommits(ctx, owner, repo, base, head, opts)
	if err != nil {
		return nil, resp, fmt.Errorf("failed to compare commits: %w", err)
	}
	return result, resp, nil
}

// GetContents implements the gitleaks.GitHubClient interface.
func (w *githubClientWrapper) GetContents(
	ctx context.Context, owner, repo, path string, opts *github.RepositoryContentGetOptions,
) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error) {
	content, dir, resp, err := w.client.Repositories.GetContents(ctx, owner, repo, path, opts)
	if err != nil {
		return nil, nil, resp, fmt.Errorf("failed to get contents: %w", err)
	}
	return content, dir, resp, nil
}
