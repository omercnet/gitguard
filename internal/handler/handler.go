package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-github/v72/github"
	"github.com/omercnet/gitguard/internal/constants"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

// SecretScanHandler handles push events to scan commits for secrets.
type SecretScanHandler struct {
	githubapp.ClientCreator
	detector *detect.Detector
}

// Handles returns the list of event types this handler can process.
func (h *SecretScanHandler) Handles() []string {
	return []string{constants.PushEventType}
}

// Handle processes push events to scan commits for secrets.
func (h *SecretScanHandler) Handle(ctx context.Context, eventType, deliveryID string, payload []byte) error {
	logger := zerolog.Ctx(ctx).With().
		Str("event_type", eventType).
		Str("delivery_id", deliveryID).
		Logger()

	// Initialize detector if needed
	if h.detector == nil {
		viperConfig := config.ViperConfig{
			Extend: config.Extend{
				UseDefault: true,
			},
		}
		cfg, err := viperConfig.Translate()
		if err != nil {
			return fmt.Errorf(constants.ErrCreateGitleaksConfig, err)
		}
		h.detector = detect.NewDetector(cfg)
	}

	// Parse push event
	var event github.PushEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf(constants.ErrUnmarshalPushEvent, err)
	}

	// Skip if no commits or not a branch push
	if len(event.Commits) == 0 || !strings.HasPrefix(event.GetRef(), constants.BranchRefPrefix) {
		logger.Debug().Msg(constants.LogMsgSkippingEvent)
		return nil
	}

	// Create GitHub client
	installationID := githubapp.GetInstallationIDFromEvent(&event)
	client, err := h.NewInstallationClient(installationID)
	if err != nil {
		return fmt.Errorf(constants.ErrCreateGitHubClient, err)
	}

	owner := event.GetRepo().GetOwner().GetLogin()
	repo := event.GetRepo().GetName()

	logger.Info().
		Str("repo", event.GetRepo().GetFullName()).
		Int("commit_count", len(event.Commits)).
		Msg(constants.LogMsgProcessingCommits)

	// Process each commit
	for _, commit := range event.Commits {
		commitSHA := commit.GetID()
		commitLogger := logger.With().Str("commit_sha", commitSHA).Logger()

		if err := h.scanCommit(ctx, client, owner, repo, commitSHA, commitLogger); err != nil {
			commitLogger.Error().Err(err).Msg(constants.LogMsgFailedScanCommit)
			// Continue with other commits
		}
	}

	return nil
}

func (h *SecretScanHandler) scanCommit(ctx context.Context, client *github.Client, owner, repo, sha string, logger zerolog.Logger) error {
	// Create check run
	checkRunID, err := h.createCheckRun(ctx, client, owner, repo, sha, logger)
	if err != nil {
		return err
	}

	// Get commit diff
	comparison, err := h.getCommitDiff(ctx, client, owner, repo, sha)
	if err != nil {
		h.updateCheckRunWithError(ctx, client, owner, repo, checkRunID, logger)
		return fmt.Errorf(constants.ErrGetCommitDiff, err)
	}

	// Scan changed files
	var allFindings []report.Finding
	filesScanned := 0

	for _, file := range comparison.Files {
		if h.shouldSkipFile(file) {
			continue
		}

		content, err := h.getFileContent(ctx, client, owner, repo, sha, file.GetFilename())
		if err != nil || content == "" {
			continue
		}

		findings := h.detector.DetectString(content)
		allFindings = append(allFindings, findings...)
		filesScanned++
	}

	// Update check run with results
	return h.updateCheckRunWithResults(ctx, client, owner, repo, checkRunID, allFindings, filesScanned, logger)
}

func (h *SecretScanHandler) createCheckRun(ctx context.Context, client *github.Client, owner, repo, sha string, logger zerolog.Logger) (int64, error) {
	checkRun := &github.CreateCheckRunOptions{
		Name:    constants.CheckRunName,
		HeadSHA: sha,
		Status:  github.Ptr(constants.StatusInProgress),
		Output: &github.CheckRunOutput{
			Title:   github.Ptr(constants.CheckRunTitleInProgress),
			Summary: github.Ptr(constants.CheckRunSummaryInProgress),
		},
	}

	createdCheck, _, err := client.Checks.CreateCheckRun(ctx, owner, repo, *checkRun)
	if err != nil {
		return 0, fmt.Errorf(constants.ErrCreateCheckRun, err)
	}

	logger.Debug().Int64("check_run_id", createdCheck.GetID()).Msg(constants.LogMsgCreatedCheckRun)
	return createdCheck.GetID(), nil
}

func (h *SecretScanHandler) getCommitDiff(ctx context.Context, client *github.Client, owner, repo, sha string) (*github.CommitsComparison, error) {
	// Try to get diff with previous commit
	comparison, _, err := client.Repositories.CompareCommits(ctx, owner, repo, sha+"~1", sha, nil)
	if err == nil {
		return comparison, nil
	}

	// For initial commits, compare with empty tree
	comparison, _, err = client.Repositories.CompareCommits(ctx, owner, repo, constants.EmptyTreeSHA, sha, nil)
	return comparison, err
}

func (h *SecretScanHandler) shouldSkipFile(file *github.CommitFile) bool {
	return file.GetStatus() == constants.FileStatusRemoved || file.GetChanges() > constants.MaxFileChanges
}

func (h *SecretScanHandler) getFileContent(ctx context.Context, client *github.Client, owner, repo, sha, filename string) (string, error) {
	opts := &github.RepositoryContentGetOptions{Ref: sha}
	fileContent, _, _, err := client.Repositories.GetContents(ctx, owner, repo, filename, opts)
	if err != nil {
		return "", err
	}

	content, err := fileContent.GetContent()
	if err != nil {
		return "", err
	}

	return content, nil
}

func (h *SecretScanHandler) updateCheckRunWithResults(ctx context.Context, client *github.Client, owner, repo string, checkRunID int64, findings []report.Finding, filesScanned int, logger zerolog.Logger) error {
	var conclusion, title, summary string

	if len(findings) == 0 {
		conclusion = constants.ConclusionSuccess
		title = constants.CheckRunTitleClean
		summary = constants.CheckRunSummaryClean
	} else {
		conclusion = constants.ConclusionFailure
		title = constants.CheckRunTitleSecrets
		summary = fmt.Sprintf(constants.CheckRunSummarySecrets, len(findings))

		// Add leak types summary (without exposing actual secrets)
		leakTypes := make(map[string]bool)
		for _, finding := range findings {
			if finding.RuleID != "" {
				leakTypes[finding.RuleID] = true
			}
		}

		if len(leakTypes) > 0 {
			summary += constants.CheckRunSummaryTypes
			for leakType := range leakTypes {
				summary += "- " + leakType + "\n"
			}
		}
	}

	updateCheck := &github.UpdateCheckRunOptions{
		Name:        constants.CheckRunName,
		Status:      github.Ptr(constants.StatusCompleted),
		Conclusion:  github.Ptr(conclusion),
		CompletedAt: &github.Timestamp{Time: time.Now()},
		Output: &github.CheckRunOutput{
			Title:   github.Ptr(title),
			Summary: github.Ptr(summary),
		},
	}

	_, _, err := client.Checks.UpdateCheckRun(ctx, owner, repo, checkRunID, *updateCheck)
	if err != nil {
		return fmt.Errorf(constants.ErrUpdateCheckRun, err)
	}

	logger.Info().
		Int64("check_run_id", checkRunID).
		Str("conclusion", conclusion).
		Int("findings", len(findings)).
		Int("files_scanned", filesScanned).
		Msg(constants.LogMsgUpdatedCheckRun)

	return nil
}

func (h *SecretScanHandler) updateCheckRunWithError(ctx context.Context, client *github.Client, owner, repo string, checkRunID int64, logger zerolog.Logger) {
	updateCheck := &github.UpdateCheckRunOptions{
		Name:       constants.CheckRunName,
		Status:     github.Ptr(constants.StatusCompleted),
		Conclusion: github.Ptr(constants.ConclusionFailure),
		Output: &github.CheckRunOutput{
			Title:   github.Ptr(constants.CheckRunTitleError),
			Summary: github.Ptr(constants.CheckRunSummaryError),
		},
	}

	if _, _, err := client.Checks.UpdateCheckRun(ctx, owner, repo, checkRunID, *updateCheck); err != nil {
		logger.Error().Err(err).Msg(constants.LogMsgErrorUpdateFailed)
	} else {
		logger.Debug().Int64("check_run_id", checkRunID).Msg(constants.LogMsgCreatedCheckRun)
	}
}
