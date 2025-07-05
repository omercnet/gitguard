package handler

import (
	"testing"

	"github.com/omercnet/gitguard/internal/constants"
)

func TestSecretScanHandlerHandles(t *testing.T) {
	handler := &SecretScanHandler{}
	events := handler.Handles()

	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}

	if events[0] != constants.PushEventType {
		t.Errorf("Expected '%s' event, got %s", constants.PushEventType, events[0])
	}
}
