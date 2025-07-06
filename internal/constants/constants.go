package constants

import "time"

const (
	// GitHub check run configuration.
	CheckRunName    = "gitguard/secret-scan"
	MaxFileChanges  = 1000
	EmptyTreeSHA    = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	BranchRefPrefix = "refs/heads/"

	// GitHub event types.
	PushEventType = "push"

	// File statuses.
	FileStatusRemoved = "removed"

	// Check run statuses and conclusions.
	StatusInProgress  = "in_progress"
	StatusCompleted   = "completed"
	ConclusionSuccess = "success"
	ConclusionFailure = "failure"

	// Check run titles and summaries.
	CheckRunTitleInProgress = "GitGuard Secret Scan"
	CheckRunTitleError      = "GitGuard Secret Scan - Error"
	CheckRunTitleClean      = "GitGuard Secret Scan - Clean"
	CheckRunTitleSecrets    = "GitGuard Secret Scan - Secrets Detected"

	CheckRunSummaryInProgress = "🔍 Scanning commit for secrets and sensitive information..."
	CheckRunSummaryError      = "❌ Failed to scan commit for secrets. Please try again."
	CheckRunSummaryClean      = "✅ No secrets or sensitive information detected in this commit."
	CheckRunSummarySecrets    = "🚨 **%d secret(s) detected** in this commit. " +
		"Please review and remove sensitive information." // #nosec G101 -- Not a credential, just a user-facing message.
	CheckRunSummaryTypes = "\n\n**Types of secrets found:**\n"

	// Error messages.
	ErrCreateGitleaksConfig = "failed to create gitleaks config: %w"
	ErrUnmarshalPushEvent   = "failed to unmarshal push event: %w"
	ErrCreateGitHubClient   = "failed to create GitHub client: %w"
	ErrGetCommitDiff        = "failed to get commit diff: %w"
	ErrCreateCheckRun       = "failed to create check run: %w"
	ErrUpdateCheckRun       = "failed to update check run: %w"

	// Full repository scan configuration.
	FullScanTimeout = 60 * time.Second
	IssueTitle      = "🚨 GitGuard: Secrets Detected in Repository"
	IssueLabel      = "security"

	// Full repository scan error messages.
	ErrCloneRepository      = "failed to clone repository: %w"
	ErrScanRepository       = "failed to scan repository: %w"
	ErrCreateIssue          = "failed to create issue: %w"
	ErrGetDefaultBranch     = "failed to get default branch: %w"
	ErrInvalidCloneURL      = "invalid clone URL"
	ErrScanTimeout          = "repository scan timed out"
	ErrGetInstallationToken = "failed to get installation token: %w"

	// Log messages.
	LogMsgSkippingEvent      = "Skipping event - no commits or not a branch push"
	LogMsgSkippingNonDefault = "Skipping event - not a push to default branch"
	LogMsgProcessingCommits  = "Processing commits for secret scanning"
	LogMsgFailedScanCommit   = "Failed to scan commit"
	LogMsgCreatedCheckRun    = "Created check run"
	LogMsgUpdatedCheckRun    = "Updated check run with scan results"
	LogMsgErrorUpdateFailed  = "Failed to update check run with error status"
	LogMsgStartingFullScan   = "Starting full repository scan"
	LogMsgFullScanComplete   = "Full repository scan completed"
	LogMsgCreatedIssue       = "Created security issue for detected secrets"
	LogMsgNoSecretsFound     = "No secrets found in full repository scan"
	LogMsgCloningRepository  = "Cloning repository for full scan"
)
