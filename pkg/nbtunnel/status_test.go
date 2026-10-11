package nbtunnel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWaitForIP(t *testing.T) {
	t.Run("returns once management accepted the peer and assigned an address", func(t *testing.T) {
		calls := 0
		status := func() (Status, error) {
			calls++
			st := Status{ManagementConnected: calls >= 2}
			if calls >= 3 {
				st.IP = "100.73.5.6"
			}
			return st, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		st, err := waitForIP(ctx, status)
		if err != nil {
			t.Fatalf("waitForIP: %v", err)
		}
		if st.IP != "100.73.5.6" || calls < 3 {
			t.Errorf("got %+v after %d polls, want the address after the third", st, calls)
		}
	})

	t.Run("reports the management error when it never joins", func(t *testing.T) {
		status := func() (Status, error) {
			return Status{ManagementError: "PermissionDenied: no peer auth method provided"}, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*peerPoll)
		defer cancel()
		_, err := waitForIP(ctx, status)
		if err == nil || !strings.Contains(err.Error(), "no peer auth method") {
			t.Fatalf("expected the management error in the message, got %v", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("expected the deadline to be wrapped, got %v", err)
		}
	})
}

func TestStatusFormat(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	st := Status{
		DeviceName:          "my-laptop",
		ManagementURL:       "https://mgmt.example.com:443",
		ManagementConnected: true,
		SignalConnected:     true,
		IP:                  "100.73.5.6",
		FQDN:                "my-laptop.example.netbird",
		PubKey:              "abc=",
		Peers: []PeerStatus{
			{FQDN: "gateway-1", IP: "100.73.24.224", Status: "Connected", Connected: true, Relayed: true, Latency: 42 * time.Millisecond, LastHandshake: now.Add(-3 * time.Second)},
			{FQDN: "gpu-box", IP: "100.73.9.9", Status: "Connecting"},
		},
	}
	out := st.Format(now)
	for _, want := range []string{
		"Management:  https://mgmt.example.com:443 (connected)",
		"NetBird IP:  100.73.5.6",
		"FQDN:        my-laptop.example.netbird",
		"Peers in the network map: 2",
		"gateway-1", "100.73.24.224", "relay", "42ms", "3s ago",
		"gpu-box", "Connecting",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	empty := Status{ManagementError: "dial tcp: connection refused"}
	if out := empty.Format(now); !strings.Contains(out, "disconnected: dial tcp: connection refused") || !strings.Contains(out, "NetBird IP:  -") {
		t.Errorf("unexpected output for a peer that never joined:\n%s", out)
	}
	if !st.Joined() || empty.Joined() {
		t.Error("Joined should follow management state plus address")
	}
}
