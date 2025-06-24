// Package gitleaks provides integration with the gitleaks secret detection library.
package gitleaks

import (
	"context"
	"fmt"

	"github.com/google/go-github/v72/github"
	"github.com/rs/zerolog"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

const (
	// Git file status.
	FileStatusRemoved = "removed"

	// File size limits.
	MaxFileChanges = 1000

	// Git empty tree SHA (used for initial commits).
	EmptyTreeSHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

	// Error messages.
	ErrFailedToGetCommitDiff = "failed to get commit diff: %w"

	// Leak summary formatting.
	LeakSummaryPrefix = "- "
)

// GitHubClient defines the interface for GitHub API operations needed by the detector.
type GitHubClient interface {
	CompareCommits(ctx context.Context, owner, repo, base, head string, opts *github.ListOptions) (
		*github.CommitsComparison, *github.Response, error)
	GetContents(ctx context.Context, owner, repo, path string, opts *github.RepositoryContentGetOptions) (
		*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error)
}

// Detector wraps the gitleaks detector with additional functionality.
type Detector struct {
	detector *detect.Detector
}

// NewDetector creates a new gitleaks detector with default configuration.
func NewDetector() *Detector {
	cfg := config.Config{}
	detector := detect.NewDetector(cfg)
	return &Detector{detector: detector}
}

// ScanResult holds the results of a secret scan.
type ScanResult struct {
	HasLeaks    bool
	LeakCount   int
	LeakSummary []string
}

// ScanCommit scans a commit for secrets using gitleaks.
func (d *Detector) ScanCommit(ctx context.Context, client GitHubClient, owner, repo, sha string,
	logger zerolog.Logger,
) (*ScanResult, error) {
	logger.Debug().
		Str("owner", owner).
		Str("repo", repo).
		Str("commit_sha", sha).
		Msg("Starting gitleaks scan for commit")

	// Get the commit diff to scan only changes
	comparison, err := d.getCommitDiff(ctx, client, owner, repo, sha)
	if err != nil {
		return nil, err
	}

	logger.Debug().
		Int("files_changed", len(comparison.Files)).
		Msg("Retrieved commit diff for scanning")

	// Scan all changed files
	findings, filesToScan := d.scanChangedFiles(ctx, client, owner, repo, sha, comparison.Files, logger)

	// Build and return results
	result := d.buildScanResult(findings)

	logger.Debug().
		Int("files_scanned", filesToScan).
		Int("total_findings", result.LeakCount).
		Bool("has_leaks", result.HasLeaks).
		Msg("Gitleaks scan completed")

	return result, nil
}

// getCommitDiff gets the commit diff, handling initial commits gracefully.
func (d *Detector) getCommitDiff(ctx context.Context, client GitHubClient, owner, repo, sha string) (
	*github.CommitsComparison, error,
) {
	// Try to get diff with previous commit
	comparison, _, err := client.CompareCommits(ctx, owner, repo, sha+"~1", sha, &github.ListOptions{})
	if err == nil {
		return comparison, nil
	}

	// For initial commits, compare with empty tree
	comparison, _, err = client.CompareCommits(ctx, owner, repo, EmptyTreeSHA, sha, &github.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf(ErrFailedToGetCommitDiff, err)
	}

	return comparison, nil
}

// scanChangedFiles scans all changed files for secrets.
func (d *Detector) scanChangedFiles(ctx context.Context, client GitHubClient, owner, repo, sha string,
	files []*github.CommitFile, logger zerolog.Logger,
) ([]report.Finding, int) {
	var allFindings []report.Finding
	filesToScan := 0

	for _, file := range files {
		if d.shouldSkipFile(file, logger) {
			continue
		}

		filename := file.GetFilename()
		logger.Trace().Str("filename", filename).Msg("Fetching file content for scanning")

		content, err := d.getFileContent(ctx, client, owner, repo, sha, filename)
		if err != nil {
			logger.Warn().Str("filename", filename).Err(err).Msg("Failed to get file content")
			continue
		}

		if content == "" {
			logger.Trace().Str("filename", filename).Msg("Skipping empty file")
			continue // Skip empty files
		}

		logger.Trace().Str("filename", filename).Int("content_length", len(content)).Msg("Scanning file content")
		findings := d.detector.DetectString(content)

		if len(findings) > 0 {
			logger.Debug().Str("filename", filename).Int("findings", len(findings)).Msg("Secrets found in file")
		}

		allFindings = append(allFindings, findings...)
		filesToScan++
	}

	return allFindings, filesToScan
}

// shouldSkipFile determines if a file should be skipped during scanning.
func (d *Detector) shouldSkipFile(file *github.CommitFile, logger zerolog.Logger) bool {
	filename := file.GetFilename()

	// Skip removed files
	if file.GetStatus() == FileStatusRemoved {
		return true
	}

	// Skip large files (over 1000 changes)
	if file.GetChanges() > MaxFileChanges {
		logger.Trace().Str("filename", filename).Int("changes", file.GetChanges()).Msg("Skipping large file")
		return true
	}

	return false
}

// getFileContent retrieves and decodes file content from GitHub.
func (d *Detector) getFileContent(ctx context.Context, client GitHubClient, owner, repo, sha, filename string) (
	string, error,
) {
	opts := &github.RepositoryContentGetOptions{Ref: sha}
	fileContent, _, _, err := client.GetContents(ctx, owner, repo, filename, opts)
	if err != nil {
		return "", fmt.Errorf("failed to get file contents: %w", err)
	}

	content, err := fileContent.GetContent()
	if err != nil {
		return "", fmt.Errorf("failed to decode file content: %w", err)
	}

	return content, nil
}

// buildScanResult builds the final scan result from findings.
func (d *Detector) buildScanResult(findings []report.Finding) *ScanResult {
	result := &ScanResult{
		HasLeaks:    len(findings) > 0,
		LeakCount:   len(findings),
		LeakSummary: []string{},
	}

	// Create summary of leak types (without exposing actual secrets)
	leakTypes := make(map[string]bool)
	for _, finding := range findings {
		if finding.RuleID != "" {
			leakTypes[finding.RuleID] = true
		}
	}

	// Convert to slice with prefix
	for leakType := range leakTypes {
		result.LeakSummary = append(result.LeakSummary, LeakSummaryPrefix+leakType)
	}

	return result
}
