package serverapp

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type cleanupFixture struct{ calls chan struct{} }

func (f cleanupFixture) DeleteExpiredSessions(context.Context, time.Time) error {
	f.calls <- struct{}{}
	return errors.New("cleanup unavailable")
}

func TestCleanupLogsFailureAndKeepsRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture := cleanupFixture{calls: make(chan struct{}, 10)}
	var logs bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		cleanSessions(ctx, fixture, slog.New(slog.NewJSONHandler(&logs, nil)), 10*time.Millisecond)
	}()
	for range 2 {
		select {
		case <-fixture.calls:
		case <-time.After(time.Second):
			t.Fatal("cleanup did not continue")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not stop")
	}
	if !strings.Contains(logs.String(), `"level":"ERROR"`) || !strings.Contains(logs.String(), "cleanup unavailable") {
		t.Fatal("cleanup failure not logged")
	}
}
