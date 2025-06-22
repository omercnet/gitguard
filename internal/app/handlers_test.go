package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-github/v72/github"
	"github.com/omercnet/gitguard/internal/app"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockGitHubClient implements gitleaks.GitHubClient for testing
// and mocks the github.Client for scanCommit.
type MockGitHubClient struct {
	mock.Mock
}

func (m *MockGitHubClient) CompareCommits(
	ctx context.Context,
	owner, repo, base, head string,
	opts *github.ListOptions,
) (*github.CommitsComparison, *github.Response, error) {
	args := m.Called(ctx, owner, repo, base, head, opts)
	if err := args.Error(2); err != nil {
		return args.Get(0).(*github.CommitsComparison), args.Get(1).(*github.Response),
			fmt.Errorf("mock CompareCommits error: %w", err)
	}
	return args.Get(0).(*github.CommitsComparison), args.Get(1).(*github.Response), nil
}

func (m *MockGitHubClient) GetContents(
	ctx context.Context,
	owner, repo, path string,
	opts *github.RepositoryContentGetOptions,
) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error) {
	args := m.Called(ctx, owner, repo, path, opts)
	if err := args.Error(3); err != nil {
		return args.Get(0).(*github.RepositoryContent), args.Get(1).([]*github.RepositoryContent),
			args.Get(2).(*github.Response), fmt.Errorf("mock GetContents error: %w", err)
	}
	return args.Get(0).(*github.RepositoryContent), args.Get(1).([]*github.RepositoryContent),
		args.Get(2).(*github.Response), nil
}

// --- Tests for GitHubClientWrapper ---.
func TestGitHubClientWrapper_Creation(t *testing.T) {
	wrapper := &app.GitHubClientWrapper{}
	assert.NotNil(t, wrapper)
}

// --- Tests for NewCommitHandler and Handles ---.
func TestNewCommitHandlerAndHandles(t *testing.T) {
	cc := &mockClientCreator{}
	h := app.NewCommitHandler(cc)
	assert.NotNil(t, h)
	assert.Equal(t, []string{"push"}, h.Handles())
}

type mockClientCreator struct{ githubapp.ClientCreator }

func (m *mockClientCreator) NewInstallationClient(_ int64) (*github.Client, error) {
	return &github.Client{}, nil
}

// --- Tests for Handle ---.
func TestHandle_NoCommits(t *testing.T) {
	h := app.NewCommitHandler(&mockClientCreator{})
	event := github.PushEvent{Commits: []*github.HeadCommit{}}
	payload, _ := json.Marshal(event)
	ctx := zerolog.New(nil).WithContext(context.Background())
	err := h.Handle(ctx, "push", "id", payload)
	assert.NoError(t, err)
}

func TestHandle_NonBranchPush(t *testing.T) {
	h := app.NewCommitHandler(&mockClientCreator{})
	event := github.PushEvent{
		Ref:     github.Ptr("refs/tags/v1.0.0"),
		Commits: []*github.HeadCommit{{SHA: github.Ptr("sha")}},
	}
	payload, _ := json.Marshal(event)
	ctx := zerolog.New(nil).WithContext(context.Background())
	err := h.Handle(ctx, "push", "id", payload)
	assert.NoError(t, err)
}

func TestHandle_InvalidPayload(t *testing.T) {
	h := app.NewCommitHandler(&mockClientCreator{})
	ctx := zerolog.New(nil).WithContext(context.Background())
	err := h.Handle(ctx, "push", "id", []byte("notjson"))
	assert.Error(t, err)
}

func TestHandle_ClientError(t *testing.T) {
	h := app.NewCommitHandler(&mockClientCreatorErr{})
	event := github.PushEvent{
		Ref:     github.Ptr("refs/heads/main"),
		Commits: []*github.HeadCommit{{SHA: github.Ptr("sha")}},
	}
	payload, _ := json.Marshal(event)
	ctx := zerolog.New(nil).WithContext(context.Background())
	err := h.Handle(ctx, "push", "id", payload)
	assert.Error(t, err)
}

type mockClientCreatorErr struct{ githubapp.ClientCreator }

func (m *mockClientCreatorErr) NewInstallationClient(_ int64) (*github.Client, error) {
	return nil, errors.New("fail")
}

// MockRepositoriesService mocks the github.RepositoriesService.
type MockRepositoriesService struct {
	mock.Mock
}

func (m *MockRepositoriesService) CompareCommits(
	ctx context.Context,
	owner, repo, base, head string,
	opts *github.ListOptions,
) (*github.CommitsComparison, *github.Response, error) {
	args := m.Called(ctx, owner, repo, base, head, opts)
	if err := args.Error(2); err != nil {
		return args.Get(0).(*github.CommitsComparison), args.Get(1).(*github.Response),
			fmt.Errorf("mock CompareCommits error: %w", err)
	}
	return args.Get(0).(*github.CommitsComparison), args.Get(1).(*github.Response), nil
}

func (m *MockRepositoriesService) GetContents(
	ctx context.Context,
	owner, repo, path string,
	opts *github.RepositoryContentGetOptions,
) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error) {
	args := m.Called(ctx, owner, repo, path, opts)
	if err := args.Error(3); err != nil {
		return args.Get(0).(*github.RepositoryContent), args.Get(1).([]*github.RepositoryContent),
			args.Get(2).(*github.Response), fmt.Errorf("mock GetContents error: %w", err)
	}
	return args.Get(0).(*github.RepositoryContent), args.Get(1).([]*github.RepositoryContent),
		args.Get(2).(*github.Response), nil
}

// MockChecksService mocks the github.ChecksService.
type MockChecksService struct {
	mock.Mock
}

func (m *MockChecksService) CreateCheckRun(
	ctx context.Context,
	owner, repo string,
	opt github.CreateCheckRunOptions,
) (*github.CheckRun, *github.Response, error) {
	args := m.Called(ctx, owner, repo, opt)
	if err := args.Error(2); err != nil {
		return args.Get(0).(*github.CheckRun), args.Get(1).(*github.Response),
			fmt.Errorf("mock CreateCheckRun error: %w", err)
	}
	return args.Get(0).(*github.CheckRun), args.Get(1).(*github.Response), nil
}

func (m *MockChecksService) UpdateCheckRun(
	ctx context.Context,
	owner, repo string,
	id int64,
	opt github.UpdateCheckRunOptions,
) (*github.CheckRun, *github.Response, error) {
	args := m.Called(ctx, owner, repo, id, opt)
	if err := args.Error(2); err != nil {
		return args.Get(0).(*github.CheckRun), args.Get(1).(*github.Response),
			fmt.Errorf("mock UpdateCheckRun error: %w", err)
	}
	return args.Get(0).(*github.CheckRun), args.Get(1).(*github.Response), nil
}
