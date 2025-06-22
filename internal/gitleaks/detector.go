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
	// Load default gitleaks configuration
	cfg := config.Config{}

	// Create detector with default config
	detector := detect.NewDetector(cfg)

	return &Detector{
		detector: detector,
	}
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
	// Get the commit diff to scan only changes
	comparison, _, err := client.CompareCommits(ctx, owner, repo, sha+"~1", sha, &github.ListOptions{})
	if err != nil {
		// For initial commits, compare with empty tree
		emptyTree := "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
		comparison, _, err = client.CompareCommits(ctx, owner, repo, emptyTree, sha, &github.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get commit diff: %w", err)
		}
	}

	// Collect all findings from scanning changed files
	var allFindings []report.Finding
	filesToScan := 0

	// Scan each changed file directly in memory
	for _, file := range comparison.Files {
		if file.GetStatus() == "removed" {
			continue // Skip deleted files
		}

		filename := file.GetFilename()

		// Skip files that are too large or binary
		if file.GetChanges() > 1000 { // Large files
			logger.Warn().Str("filename", filename).Int("changes", file.GetChanges()).Msg("Skipping large file")
			continue
		}

		// Get file content
		opts := &github.RepositoryContentGetOptions{Ref: sha}
		fileContent, _, _, err := client.GetContents(ctx, owner, repo, filename, opts)
		if err != nil {
			logger.Warn().Str("filename", filename).Err(err).Msg("Failed to get file content")
			continue
		}

		content, err := fileContent.GetContent()
		if err != nil {
			logger.Warn().Str("filename", filename).Err(err).Msg("Failed to decode file content")
			continue
		}

		if content == "" {
			continue // Skip empty files
		}

		// Scan content directly in memory using gitleaks detector
		findings := d.detector.DetectString(content)
		allFindings = append(allFindings, findings...)
		filesToScan++
	}

	// Process results
	result := &ScanResult{
		HasLeaks:    len(allFindings) > 0,
		LeakCount:   len(allFindings),
		LeakSummary: []string{},
	}

	// Create summary of leak types (without exposing actual secrets)
	leakTypes := make(map[string]bool)
	for _, finding := range allFindings {
		if finding.RuleID != "" {
			leakTypes[finding.RuleID] = true
		}
	}

	// Convert to slice
	for leakType := range leakTypes {
		result.LeakSummary = append(result.LeakSummary, "- "+leakType)
	}

	logger.Info().
		Int("files_scanned", filesToScan).
		Int("total_findings", result.LeakCount).
		Bool("has_leaks", result.HasLeaks).
		Msg("Gitleaks scan completed")

	return result, nil
}
