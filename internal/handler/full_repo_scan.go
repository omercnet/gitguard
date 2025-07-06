package handler

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/go-github/v72/github"
	"github.com/omercnet/gitguard/internal/constants"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

// Package-level variables for file filtering to avoid duplication.
var (
	// binaryExtensions contains file extensions that should be skipped during scanning.
	binaryExtensions = []string{
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
		".exe", ".dll", ".so", ".dylib",
		".mp3", ".mp4", ".avi", ".mov", ".wmv",
		".woff", ".woff2", ".ttf", ".eot",
	}

	// skipPaths contains directory paths that should be skipped during scanning.
	skipPaths = []string{
		"node_modules/", "vendor/", ".git/", "dist/", "build/",
		"target/", "bin/", "obj/", ".gradle/", "__pycache__/",
	}
)

// FullRepoScanHandler handles push events to default branch for full repository scanning.
type FullRepoScanHandler struct {
	githubapp.ClientCreator
	detector *detect.Detector
}

// Handles returns the list of event types this handler can process.
func (h *FullRepoScanHandler) Handles() []string {
	return []string{constants.PushEventType}
}

// Handle processes push events to default branch for full repository scanning.
func (h *FullRepoScanHandler) Handle(ctx context.Context, eventType, deliveryID string, payload []byte) error {
	logger := zerolog.Ctx(ctx).With().
		Str("event_type", eventType).
		Str("delivery_id", deliveryID).
		Str("handler", "full_repo_scan").
		Logger()

	// Initialize detector if needed
	if h.detector == nil {
		detector, err := initializeDetector()
		if err != nil {
			return err
		}
		h.detector = detector
	}

	// Parse push event
	event, err := parsePushEvent(payload)
	if err != nil {
		return err
	}

	// Skip if no commits or not a branch push
	if len(event.Commits) == 0 || !strings.HasPrefix(event.GetRef(), constants.BranchRefPrefix) {
		logger.Debug().Msg(constants.LogMsgSkippingEvent)
		return nil
	}

	// Check if this is a push to the default branch
	defaultBranch := event.GetRepo().GetDefaultBranch()
	pushedBranch := strings.TrimPrefix(event.GetRef(), constants.BranchRefPrefix)

	if defaultBranch != pushedBranch {
		logger.Debug().
			Str("default_branch", defaultBranch).
			Str("pushed_branch", pushedBranch).
			Msg(constants.LogMsgSkippingNonDefault)
		return nil
	}

	// Create GitHub client
	client, err := createGitHubClient(h.ClientCreator, event)
	if err != nil {
		return err
	}

	owner := event.GetRepo().GetOwner().GetLogin()
	repo := event.GetRepo().GetName()

	logger.Info().
		Str("repo", event.GetRepo().GetFullName()).
		Str("branch", pushedBranch).
		Msg(constants.LogMsgStartingFullScan)

	// Perform full repository scan with timeout
	ctx, cancel := context.WithTimeout(ctx, constants.FullScanTimeout)
	defer cancel()

	err = h.scanFullRepository(ctx, client, owner, repo, event, logger)
	if err != nil {
		// Check for timeout error and return a more specific error message
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf(constants.ErrScanTimeout)
		}
		return err
	}

	return nil
}

func (h *FullRepoScanHandler) scanFullRepository(
	ctx context.Context,
	client *github.Client,
	owner, repo string,
	event *github.PushEvent,
	logger zerolog.Logger,
) error {
	// Get repository details for clone URL and token
	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return fmt.Errorf(constants.ErrGetDefaultBranch, err)
	}

	cloneURL := repository.GetCloneURL()
	if cloneURL == "" {
		return fmt.Errorf(constants.ErrInvalidCloneURL)
	}

	// Get installation token for cloning
	token, err := h.getInstallationToken(ctx, client, event)
	if err != nil {
		return fmt.Errorf(constants.ErrGetInstallationToken, err)
	}

	logger.Debug().
		Str("clone_url", cloneURL).
		Msg(constants.LogMsgCloningRepository)

	// Clone repository in memory
	memStorage := memory.NewStorage()

	gitRepo, err := git.CloneContext(ctx, memStorage, nil, &git.CloneOptions{
		URL: cloneURL,
		Auth: &http.BasicAuth{
			Username: "git",
			Password: token,
		},
	})
	if err != nil {
		return fmt.Errorf(constants.ErrCloneRepository, err)
	}

	// Scan repository for secrets
	findings, err := h.scanGitRepository(gitRepo)
	if err != nil {
		return fmt.Errorf(constants.ErrScanRepository, err)
	}

	logger.Info().
		Int("findings", len(findings)).
		Msg(constants.LogMsgFullScanComplete)

	// Create issue if secrets are found
	if len(findings) > 0 {
		return h.createSecurityIssue(ctx, client, owner, repo, findings, logger)
	}

	logger.Info().Msg(constants.LogMsgNoSecretsFound)
	return nil
}

func (h *FullRepoScanHandler) getInstallationToken(
	ctx context.Context, client *github.Client, event *github.PushEvent,
) (string, error) {
	// Get installation ID from the webhook event
	installationID := githubapp.GetInstallationIDFromEvent(event)

	// Create access token for this installation
	token, _, err := client.Apps.CreateInstallationToken(ctx, installationID, &github.InstallationTokenOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create installation token for installation %d: %w", installationID, err)
	}

	return token.GetToken(), nil
}

func (h *FullRepoScanHandler) scanGitRepository(gitRepo *git.Repository) ([]report.Finding, error) {
	var allFindings []report.Finding

	// Get the head reference
	ref, err := gitRepo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get head reference: %w", err)
	}

	// Get the commit object
	commit, err := gitRepo.CommitObject(ref.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to get commit object: %w", err)
	}

	// Get the tree from the commit
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get tree: %w", err)
	}

	// Walk through all files in the repository
	err = tree.Files().ForEach(func(file *object.File) error {
		// Skip files we shouldn't scan
		if h.shouldSkipFile(file) {
			return nil
		}

		content, err := file.Contents()
		if err != nil {
			// Skip files we can't read
			return fmt.Errorf("failed to read file contents: %w", err)
		}

		// Create a temporary finding with file information for gitleaks
		findings := h.detector.DetectString(content)

		// Update the file path in findings
		for i := range findings {
			findings[i].File = file.Name
		}

		allFindings = append(allFindings, findings...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan repository files: %w", err)
	}

	return allFindings, nil
}

func (h *FullRepoScanHandler) createSecurityIssue(
	ctx context.Context,
	client *github.Client,
	owner, repo string,
	findings []report.Finding,
	logger zerolog.Logger,
) error {
	// Check if a GitGuard security issue already exists
	existingIssue, err := h.findExistingSecurityIssue(ctx, client, owner, repo)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to check for existing security issues, proceeding to create new issue")
	} else if existingIssue != nil {
		logger.Info().
			Int("existing_issue_number", existingIssue.GetNumber()).
			Msg("Security issue already exists, skipping creation")
		return nil
	}

	// Create issue body
	body := h.buildIssueBody(findings)

	issueRequest := &github.IssueRequest{
		Title:  github.Ptr(constants.IssueTitle),
		Body:   github.Ptr(body),
		Labels: &[]string{constants.IssueLabel},
	}

	issue, _, err := client.Issues.Create(ctx, owner, repo, issueRequest)
	if err != nil {
		return fmt.Errorf(constants.ErrCreateIssue, err)
	}

	logger.Info().
		Int("issue_number", issue.GetNumber()).
		Int("findings", len(findings)).
		Msg(constants.LogMsgCreatedIssue)

	return nil
}

func (h *FullRepoScanHandler) buildIssueBody(findings []report.Finding) string {
	body := "## 🚨 Security Alert: Secrets Detected\n\n"
	body += "GitGuard has detected potential secrets in your repository during a full scan. "
	body += "Please review these findings and take appropriate action.\n\n"
	body += fmt.Sprintf("**Total findings:** %d\n\n", len(findings))

	// Group findings by rule ID
	ruleGroups := make(map[string][]report.Finding)
	for _, finding := range findings {
		ruleID := finding.RuleID
		if ruleID == "" {
			ruleID = "unknown"
		}
		ruleGroups[ruleID] = append(ruleGroups[ruleID], finding)
	}

	body += "### Detected Secret Types\n\n"
	for ruleID, ruleFindings := range ruleGroups {
		body += fmt.Sprintf("- **%s**: %d occurrence(s)\n", ruleID, len(ruleFindings))
	}

	body += "\n### File Locations\n\n"
	for _, finding := range findings {
		filename := finding.File
		if filename == "" {
			filename = "unknown file"
		}
		body += fmt.Sprintf("- `%s` (line %d)\n", filename, finding.StartLine)
	}

	body += "\n### Recommended Actions\n\n"
	body += "1. **Immediately rotate** any exposed credentials\n"
	body += "2. **Remove secrets** from the repository history\n"
	body += "3. **Use environment variables** or secure secret management\n"
	body += "4. **Add secrets to .gitignore** to prevent future commits\n"
	body += "5. **Review commit history** for other potential exposures\n\n"
	body += "### Important Notes\n\n"
	body += "- This issue was created automatically by GitGuard\n"
	body += "- Secrets may be visible in commit history even after removal\n"
	body += "- Consider using tools like `git filter-branch` or `BFG Repo-Cleaner` for history cleanup\n"

	return body
}

func (h *FullRepoScanHandler) findExistingSecurityIssue(
	ctx context.Context,
	client *github.Client,
	owner, repo string,
) (*github.Issue, error) {
	// Search for open issues with our title and label
	opts := &github.IssueListByRepoOptions{
		State:  "open",
		Labels: []string{constants.IssueLabel},
		ListOptions: github.ListOptions{
			PerPage: 10, // We only need to check a few recent issues
		},
	}

	issues, _, err := client.Issues.ListByRepo(ctx, owner, repo, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list repository issues: %w", err)
	}

	// Look for issues with our specific title
	for _, issue := range issues {
		if issue.GetTitle() == constants.IssueTitle {
			return issue, nil
		}
	}

	return nil, nil
}

func (h *FullRepoScanHandler) shouldSkipFile(file *object.File) bool {
	// Skip large files
	if file.Size > constants.MaxFileChanges {
		return true
	}

	filename := file.Name

	for _, ext := range binaryExtensions {
		if strings.HasSuffix(strings.ToLower(filename), ext) {
			return true
		}
	}

	// Skip common directories that usually contain binaries or dependencies
	for _, skipPath := range skipPaths {
		if strings.Contains(filename, skipPath) {
			return true
		}
	}

	return false
}
