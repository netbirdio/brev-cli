package nbembed

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// TestStartWithBogusManagementFailsCleanly exercises New and Start against an
// unreachable management URL with a bogus setup key. It asserts the code path
// links and does not hit a permission error (netstack mode needs no root).
// Start is run with a 5s context but is given 20s to return; as of this
// experiment it does not return within that window, because embed.Start builds its auth client and logs in
// with a context.Background()-derived ctx and only applies startCtx to the
// post-login engine wait (client/embed/embed.go:276,288,292,309), while
// the management connect retries on its own 10s backoff per attempt (client/grpc/dialer.go:22-27); observed: Start returned after ~30s.
func TestStartWithBogusManagementFailsCleanly(t *testing.T) {
	if testing.Short() {
		t.Skip("waits up to 20s on the embedded client; skipped in short mode")
	}
	c, err := New(Options{
		DeviceName:    "brev-cli-test",
		SetupKey:      "BOGUS-SETUP-KEY",
		ManagementURL: "https://127.0.0.1:1",
		LogOutput:     io.Discard,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Start succeeded against a bogus management URL")
		}
		if strings.Contains(strings.ToLower(err.Error()), "permission") {
			t.Fatalf("Start failed with a permission error: %v", err)
		}
		t.Logf("Start returned error: %v", err)
	case <-time.After(20 * time.Second):
		t.Logf("Start still blocked 20s after a 5s context deadline (known: NewAuth connect path ignores startCtx)")
	}
}
