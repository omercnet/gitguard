package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/omercnet/gitguard/internal/app"
	"github.com/rs/zerolog"
)

func TestNewServer(t *testing.T) {
	cfg := &app.Config{}
	cfg.Server.Port = 8080
	logger := zerolog.Nop()
	s := app.NewServer(cfg, logger)

	if s == nil {
		t.Fatal("Expected server to be created")
	}
}

func TestServerSetup(t *testing.T) {
	cfg := &app.Config{}
	cfg.Server.Port = 8080
	logger := zerolog.Nop()
	s := app.NewServer(cfg, logger)

	err := s.Setup(nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestShutdown(_ *testing.T) {
	cfg := &app.Config{}
	cfg.Server.Port = 8080
	logger := zerolog.Nop()
	s := app.NewServer(cfg, logger)
	err := s.Setup(nil)
	if err != nil {
		return
	}
	_ = s.Shutdown(context.Background())
}

func TestStart(_ *testing.T) {
	cfg := &app.Config{}
	cfg.Server.Port = 0 // Use random port
	logger := zerolog.Nop()
	s := app.NewServer(cfg, logger)
	err := s.Setup(nil)
	if err != nil {
		return
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = s.Shutdown(context.Background())
	}()

	_ = s.Start()
}
