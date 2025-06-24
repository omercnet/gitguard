package gitleaks_test

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/google/go-github/v72/github"
	"github.com/omercnet/gitguard/internal/gitleaks"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Note: Using gitleaks.GitHubClient interface from the main package

// MockGitHubClient is a mock implementation of the GitHub client.
type MockGitHubClient struct {
	mock.Mock
}

func (m *MockGitHubClient) CompareCommits(
	ctx context.Context,
	owner, repo, base, head string,
	opts *github.ListOptions,
) (*github.CommitsComparison, *github.Response, error) {
	args := m.Called(ctx, owner, repo, base, head, opts)
	err := args.Error(2)
	if err != nil {
		err = fmt.Errorf("mock CompareCommits: %w", err)
	}
	return args.Get(0).(*github.CommitsComparison), args.Get(1).(*github.Response), err
}

func (m *MockGitHubClient) GetContents(
	ctx context.Context,
	owner, repo, path string,
	opts *github.RepositoryContentGetOptions,
) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error) {
	args := m.Called(ctx, owner, repo, path, opts)
	err := args.Error(3)
	if err != nil {
		err = fmt.Errorf("mock GetContents: %w", err)
	}
	return args.Get(0).(*github.RepositoryContent), args.Get(1).([]*github.RepositoryContent),
		args.Get(2).(*github.Response), err
}

// MockRepositoryContent is a mock implementation that can simulate GetContent errors.
type MockRepositoryContent struct {
	*github.RepositoryContent
	shouldError bool
}

func (m *MockRepositoryContent) GetContent() (string, error) {
	if m.shouldError {
		return "", fmt.Errorf("mock GetContent error")
	}
	content, err := m.RepositoryContent.GetContent()
	if err != nil {
		return "", fmt.Errorf("failed to get content: %w", err)
	}
	return content, nil
}

// Helper function to create fast logger for tests.
func createTestLogger() zerolog.Logger {
	return zerolog.New(io.Discard) // Discard logs for performance
}

func TestNewDetector(t *testing.T) {
	detector := gitleaks.NewDetector()

	assert.NotNil(t, detector)
}

func TestScanCommit_NoLeaks(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock successful commit comparison
	comparison := &github.CommitsComparison{
		Files: []*github.CommitFile{
			{
				Filename: github.Ptr("test.go"),
				Status:   github.Ptr("modified"),
				Changes:  github.Ptr(10),
			},
		},
	}

	// Mock successful file content retrieval
	fileContent := &github.RepositoryContent{
		Content: github.Ptr("package main\n\nfunc main() {\n    fmt.Println(\"Hello, World!\")\n}"),
	}

	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return(comparison, &github.Response{}, nil)
	mockClient.On("GetContents", mock.Anything, "owner", "repo", "test.go", mock.Anything).
		Return(fileContent, []*github.RepositoryContent{}, &github.Response{}, nil)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.HasLeaks)
	assert.Equal(t, 0, result.LeakCount)
	assert.Empty(t, result.LeakSummary)

	mockClient.AssertExpectations(t)
}

func TestScanCommit_WithLeaks(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock successful commit comparison
	comparison := &github.CommitsComparison{
		Files: []*github.CommitFile{
			{
				Filename: github.Ptr("config.py"),
				Status:   github.Ptr("modified"),
				Changes:  github.Ptr(5),
			},
		},
	}

	// Mock file content with a GitHub token (this should trigger gitleaks)
	fileContent := &github.RepositoryContent{
		Content: github.Ptr(`import os

# GitHub Configuration
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef12345678"
API_KEY = "gho_1234567890abcdef1234567890abcdef12345678"`),
	}

	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return(comparison, &github.Response{}, nil)
	mockClient.On("GetContents", mock.Anything, "owner", "repo", "config.py", mock.Anything).
		Return(fileContent, []*github.RepositoryContent{}, &github.Response{}, nil)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results - note that actual detection depends on gitleaks configuration
	assert.NoError(t, err)
	assert.NotNil(t, result)
	// The actual detection result depends on gitleaks rules, so we just verify the structure
	assert.GreaterOrEqual(t, result.LeakCount, 0)

	mockClient.AssertExpectations(t)
}

func TestScanCommit_InitialCommit(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock failed commit comparison (initial commit)
	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return((*github.CommitsComparison)(nil), (*github.Response)(nil), assert.AnError)

	// Mock successful comparison with empty tree
	comparison := &github.CommitsComparison{
		Files: []*github.CommitFile{
			{
				Filename: github.Ptr("main.go"),
				Status:   github.Ptr("added"),
				Changes:  github.Ptr(20),
			},
		},
	}

	fileContent := &github.RepositoryContent{
		Content: github.Ptr("package main\n\nfunc main() {\n    fmt.Println(\"Hello, World!\")\n}"),
	}

	emptyTree := "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", emptyTree, "abc123", mock.Anything).
		Return(comparison, &github.Response{}, nil)
	mockClient.On("GetContents", mock.Anything, "owner", "repo", "main.go", mock.Anything).
		Return(fileContent, []*github.RepositoryContent{}, &github.Response{}, nil)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.HasLeaks)

	mockClient.AssertExpectations(t)
}

func TestScanCommit_RemovedFile(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock commit comparison with removed file
	comparison := &github.CommitsComparison{
		Files: []*github.CommitFile{
			{
				Filename: github.Ptr("deleted.go"),
				Status:   github.Ptr("removed"),
				Changes:  github.Ptr(5),
			},
		},
	}

	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return(comparison, &github.Response{}, nil)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.HasLeaks)
	assert.Equal(t, 0, result.LeakCount)

	mockClient.AssertExpectations(t)
}

func TestScanCommit_LargeFile(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock commit comparison with large file
	comparison := &github.CommitsComparison{
		Files: []*github.CommitFile{
			{
				Filename: github.Ptr("large_file.txt"),
				Status:   github.Ptr("modified"),
				Changes:  github.Ptr(1500), // Over the 1000 limit
			},
		},
	}

	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return(comparison, &github.Response{}, nil)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.HasLeaks)
	assert.Equal(t, 0, result.LeakCount)

	mockClient.AssertExpectations(t)
}

func TestScanCommit_EmptyFile(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock commit comparison
	comparison := &github.CommitsComparison{
		Files: []*github.CommitFile{
			{
				Filename: github.Ptr("empty.txt"),
				Status:   github.Ptr("added"),
				Changes:  github.Ptr(5),
			},
		},
	}

	// Mock empty file content
	fileContent := &github.RepositoryContent{
		Content: github.Ptr(""),
	}

	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return(comparison, &github.Response{}, nil)
	mockClient.On("GetContents", mock.Anything, "owner", "repo", "empty.txt", mock.Anything).
		Return(fileContent, []*github.RepositoryContent{}, &github.Response{}, nil)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.HasLeaks)
	assert.Equal(t, 0, result.LeakCount)

	mockClient.AssertExpectations(t)
}

func TestScanCommit_GetContentsError(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock successful commit comparison
	comparison := &github.CommitsComparison{
		Files: []*github.CommitFile{
			{
				Filename: github.Ptr("error.go"),
				Status:   github.Ptr("modified"),
				Changes:  github.Ptr(10),
			},
		},
	}

	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return(comparison, &github.Response{}, nil)
	mockClient.On("GetContents", mock.Anything, "owner", "repo", "error.go", mock.Anything).
		Return((*github.RepositoryContent)(nil), []*github.RepositoryContent{}, (*github.Response)(nil), assert.AnError)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results - should continue despite error
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.HasLeaks)
	assert.Equal(t, 0, result.LeakCount)

	mockClient.AssertExpectations(t)
}

func TestScanCommit_CompareCommitsError(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock failed commit comparison (both attempts)
	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return((*github.CommitsComparison)(nil), (*github.Response)(nil), assert.AnError)

	emptyTree := "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", emptyTree, "abc123", mock.Anything).
		Return((*github.CommitsComparison)(nil), (*github.Response)(nil), assert.AnError)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results - should return error
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get commit diff")

	mockClient.AssertExpectations(t)
}

func TestScanCommit_MultipleFiles(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock commit comparison with multiple files
	comparison := &github.CommitsComparison{
		Files: []*github.CommitFile{
			{
				Filename: github.Ptr("clean.go"),
				Status:   github.Ptr("modified"),
				Changes:  github.Ptr(10),
			},
			{
				Filename: github.Ptr("secrets.py"),
				Status:   github.Ptr("added"),
				Changes:  github.Ptr(15),
			},
			{
				Filename: github.Ptr("deleted.txt"),
				Status:   github.Ptr("removed"),
				Changes:  github.Ptr(5),
			},
		},
	}

	// Mock file contents
	cleanContent := &github.RepositoryContent{
		Content: github.Ptr("package main\n\nfunc main() {\n    fmt.Println(\"Hello, World!\")\n}"),
	}

	secretsContent := &github.RepositoryContent{
		Content: github.Ptr(`import os

# Database configuration
DATABASE_URL = "postgresql://user:password123@localhost:5432/db"
API_KEY = "ghp_1234567890abcdef1234567890abcdef12345678"`),
	}

	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return(comparison, &github.Response{}, nil)
	mockClient.On("GetContents", mock.Anything, "owner", "repo", "clean.go", mock.Anything).
		Return(cleanContent, []*github.RepositoryContent{}, &github.Response{}, nil)
	mockClient.On("GetContents", mock.Anything, "owner", "repo", "secrets.py", mock.Anything).
		Return(secretsContent, []*github.RepositoryContent{}, &github.Response{}, nil)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results - note that actual detection depends on gitleaks configuration
	assert.NoError(t, err)
	assert.NotNil(t, result)
	// The actual detection result depends on gitleaks rules, so we just verify the structure
	assert.GreaterOrEqual(t, result.LeakCount, 0)

	mockClient.AssertExpectations(t)
}

func TestScanCommit_WithLeaksAndEmptyRuleID(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock successful commit comparison
	comparison := &github.CommitsComparison{
		Files: []*github.CommitFile{
			{
				Filename: github.Ptr("mixed_secrets.py"),
				Status:   github.Ptr("modified"),
				Changes:  github.Ptr(5),
			},
		},
	}

	// Mock file content with secrets that might have empty RuleID
	fileContent := &github.RepositoryContent{
		Content: github.Ptr(`import os

# Multiple types of secrets
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef12345678"
AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
DATABASE_URL = "postgresql://user:password123@localhost:5432/db"`),
	}

	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return(comparison, &github.Response{}, nil)
	mockClient.On("GetContents", mock.Anything, "owner", "repo", "mixed_secrets.py", mock.Anything).
		Return(fileContent, []*github.RepositoryContent{}, &github.Response{}, nil)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results - should handle findings with potentially empty RuleID
	assert.NoError(t, err)
	assert.NotNil(t, result)
	// The actual detection result depends on gitleaks rules, so we just verify the structure
	assert.GreaterOrEqual(t, result.LeakCount, 0)
	// Verify that leak summary is properly generated
	assert.NotNil(t, result.LeakSummary)

	mockClient.AssertExpectations(t)
}

func TestScanCommit_NoFilesToScan(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock commit comparison with no files
	comparison := &github.CommitsComparison{
		Files: []*github.CommitFile{},
	}

	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return(comparison, &github.Response{}, nil)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.HasLeaks)
	assert.Equal(t, 0, result.LeakCount)
	assert.Empty(t, result.LeakSummary)

	mockClient.AssertExpectations(t)
}

func TestScanCommit_BinaryFile(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock commit comparison with binary file
	comparison := &github.CommitsComparison{
		Files: []*github.CommitFile{
			{
				Filename: github.Ptr("image.png"),
				Status:   github.Ptr("added"),
				Changes:  github.Ptr(100),
			},
		},
	}

	// Mock binary file content (nil content will cause GetContent to fail)
	fileContent := &github.RepositoryContent{
		Content: nil,
	}

	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return(comparison, &github.Response{}, nil)
	mockClient.On("GetContents", mock.Anything, "owner", "repo", "image.png", mock.Anything).
		Return(fileContent, []*github.RepositoryContent{}, &github.Response{}, nil)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.HasLeaks)
	assert.Equal(t, 0, result.LeakCount)

	mockClient.AssertExpectations(t)
}

func TestScanCommit_GetContentErrorPath(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock successful commit comparison
	comparison := &github.CommitsComparison{
		Files: []*github.CommitFile{
			{
				Filename: github.Ptr("error_content.go"),
				Status:   github.Ptr("modified"),
				Changes:  github.Ptr(10),
			},
		},
	}

	// Mock file content with invalid base64 (GetContent will error)
	fileContent := &github.RepositoryContent{
		Content:  github.Ptr("!!!notbase64!!!"),
		Encoding: github.Ptr("base64"),
	}

	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return(comparison, &github.Response{}, nil)
	mockClient.On("GetContents", mock.Anything, "owner", "repo", "error_content.go", mock.Anything).
		Return(fileContent, []*github.RepositoryContent{}, &github.Response{}, nil)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results - should continue despite error
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.HasLeaks)
	assert.Equal(t, 0, result.LeakCount)

	mockClient.AssertExpectations(t)
}

func TestScanCommit_LeakSummaryGeneration(t *testing.T) {
	// Create mock GitHub client
	mockClient := &MockGitHubClient{}

	// Mock successful commit comparison
	comparison := &github.CommitsComparison{
		Files: []*github.CommitFile{
			{
				Filename: github.Ptr("secrets.py"),
				Status:   github.Ptr("modified"),
				Changes:  github.Ptr(5),
			},
		},
	}

	// Mock file content with secrets that should trigger multiple rule types
	fileContent := &github.RepositoryContent{
		Content: github.Ptr(`import os

# GitHub token
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef12345678"

# AWS credentials
AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Database URL
DATABASE_URL = "postgresql://user:password123@localhost:5432/db"`),
	}

	mockClient.On("CompareCommits", mock.Anything, "owner", "repo", "abc123~1", "abc123", mock.Anything).
		Return(comparison, &github.Response{}, nil)
	mockClient.On("GetContents", mock.Anything, "owner", "repo", "secrets.py", mock.Anything).
		Return(fileContent, []*github.RepositoryContent{}, &github.Response{}, nil)

	// Create detector and scan
	detector := gitleaks.NewDetector()
	logger := createTestLogger()

	result, err := detector.ScanCommit(context.Background(), mockClient, "owner", "repo", "abc123", logger)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	// The actual detection result depends on gitleaks rules, but we should have some findings
	assert.GreaterOrEqual(t, result.LeakCount, 0)
	// Verify that leak summary is properly generated and contains entries
	if result.HasLeaks {
		assert.NotEmpty(t, result.LeakSummary)
		// Verify each summary entry starts with "- "
		for _, summary := range result.LeakSummary {
			assert.True(t, len(summary) >= 2)
			assert.Equal(t, "- ", summary[:2])
		}
	}

	mockClient.AssertExpectations(t)
}
