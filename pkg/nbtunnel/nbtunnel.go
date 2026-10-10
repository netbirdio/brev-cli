// Package nbtunnel runs the NetBird client embedded in brev-cli so a device can
// reach Brev machines over the NetBird overlay without installing the netbird
// daemon. The peer identity lives under ~/.brev/netbird: brev register creates
// it once from the setup key in Brev's registration command, and brev ssh
// --netbird starts it for the length of one session.
package nbtunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	netbird "github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/util/netrelay"

	"github.com/brevdev/brev-cli/pkg/files"
)

const (
	dirName      = "netbird"
	identityFile = "tunnel.json"
	configFile   = "config.json"
	stateFile    = "state.json"
	logFile      = "tunnel.log"
	lockFile     = "lock"

	startTimeout = 45 * time.Second
	stopTimeout  = 5 * time.Second
	dialTimeout  = 20 * time.Second
	peerPoll     = 500 * time.Millisecond

	envDisableNATMapper = "NB_DISABLE_NAT_MAPPER"
)

var (
	// ErrNotRegistered means no embedded tunnel identity exists on this device.
	ErrNotRegistered = errors.New("the embedded Brev tunnel is not set up on this device; run 'brev register --embedded' first")
	// ErrLocked means another brev process is already running the embedded peer.
	ErrLocked = errors.New("another brev command is already using the embedded Brev tunnel; wait for it to finish")
)

// Dir returns the directory holding the embedded tunnel identity for userHome.
func Dir(userHome string) string {
	return filepath.Join(files.GetBrevHome(userHome), dirName)
}

// Identity is what brev register persists for later sessions. The WireGuard
// private key stays in the netbird config file next to it.
type Identity struct {
	DeviceName    string `json:"device_name"`
	ManagementURL string `json:"management_url"`
	RegisteredAt  string `json:"registered_at"`
}

// IsRegistered reports whether dir holds a usable identity.
func IsRegistered(dir string) bool {
	if _, err := readIdentity(dir); err != nil {
		return false
	}
	_, err := readPrivateKey(dir)
	return err == nil
}

// Remove deletes the identity, the netbird config and state under dir.
func Remove(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove %s: %w", dir, err)
	}
	return nil
}

// Register creates a fresh peer identity under dir by logging in to management
// once with the setup key, then stops the client. The setup key itself is never
// written to disk; later sessions log in with the persisted private key.
func Register(ctx context.Context, dir, deviceName string, creds Credentials) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	unlock, err := lock(dir)
	if err != nil {
		return err
	}
	defer unlock()

	// A previous identity would be reused by the config loader and could
	// collide with a peer management still knows; start from nothing.
	for _, name := range []string{identityFile, configFile, stateFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale %s: %w", name, err)
		}
	}

	logW, closeLog, err := openLog(dir)
	if err != nil {
		return err
	}
	defer closeLog()

	client, err := newClient(dir, clientOptions{
		deviceName:    deviceName,
		managementURL: creds.ManagementURL,
		setupKey:      creds.SetupKey,
	}, logW)
	if err != nil {
		return err
	}
	if err := startBounded(ctx, client); err != nil {
		return err
	}
	stopClient(client)

	id := Identity{
		DeviceName:    deviceName,
		ManagementURL: creds.ManagementURL,
		RegisteredAt:  time.Now().UTC().Format(time.RFC3339),
	}
	return writeJSON(filepath.Join(dir, identityFile), id)
}

// Tunnel is the embedded peer for one brev session.
type Tunnel struct {
	id     Identity
	client *netbird.Client
	dial   func(ctx context.Context, addr string) (net.Conn, error)
	peers  func() ([]peerInfo, error)

	unlock   func()
	closeLog func()

	mu       sync.Mutex
	started  bool
	listener net.Listener
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// Open loads the identity under dir and prepares the client. It does not
// connect; call Start.
func Open(dir string) (*Tunnel, error) {
	id, err := readIdentity(dir)
	if err != nil {
		return nil, err
	}
	privateKey, err := readPrivateKey(dir)
	if err != nil {
		return nil, err
	}
	unlock, err := lock(dir)
	if err != nil {
		return nil, err
	}
	logW, closeLog, err := openLog(dir)
	if err != nil {
		unlock()
		return nil, err
	}
	client, err := newClient(dir, clientOptions{
		deviceName:    id.DeviceName,
		managementURL: id.ManagementURL,
		privateKey:    privateKey,
	}, logW)
	if err != nil {
		closeLog()
		unlock()
		return nil, err
	}

	t := &Tunnel{id: id, client: client, unlock: unlock, closeLog: closeLog}
	t.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		return client.Dial(ctx, "tcp", addr)
	}
	t.peers = t.clientPeers
	return t, nil
}

// Identity returns the persisted identity this tunnel runs as.
func (t *Tunnel) Identity() Identity {
	return t.id
}

// Start logs in to management and brings the overlay up.
func (t *Tunnel) Start(ctx context.Context) error {
	if err := startBounded(ctx, t.client); err != nil {
		return err
	}
	t.mu.Lock()
	t.started = true
	t.mu.Unlock()
	return nil
}

// WaitForPeer blocks until the peer at ip reports a connected tunnel, or ctx
// expires. A peer that never appears is not in this device's network map,
// which is a Brev policy question rather than a connectivity one.
func (t *Tunnel) WaitForPeer(ctx context.Context, ip netip.Addr) error {
	return waitForPeer(ctx, ip, t.peers)
}

// Dial opens a TCP connection to addr over the overlay.
func (t *Tunnel) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return t.dial(ctx, addr)
}

// ListenLoopback starts a listener on 127.0.0.1 that relays every accepted
// connection to target over the overlay, and returns its address. OpenSSH is
// pointed at it with HostName and Port overrides so the rest of the user's
// ssh_config entry still applies.
func (t *Tunnel) ListenLoopback(target string) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listen on loopback: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	t.mu.Lock()
	t.listener = ln
	t.cancel = cancel
	t.mu.Unlock()

	t.wg.Add(1)
	go t.serve(ctx, ln, target)
	return ln.Addr().String(), nil
}

// Close stops the listener, the relays and the embedded client, and releases
// the identity lock. It is safe to call more than once.
func (t *Tunnel) Close() {
	t.mu.Lock()
	cancel, ln, started := t.cancel, t.listener, t.started
	t.cancel, t.listener, t.started = nil, nil, false
	t.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if ln != nil {
		_ = ln.Close()
	}
	t.wg.Wait()
	if started {
		stopClient(t.client)
	}
	if t.closeLog != nil {
		t.closeLog()
		t.closeLog = nil
	}
	if t.unlock != nil {
		t.unlock()
		t.unlock = nil
	}
}

func (t *Tunnel) serve(ctx context.Context, ln net.Listener, target string) {
	defer t.wg.Done()
	for {
		local, err := ln.Accept()
		if err != nil {
			return
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.relay(ctx, local, target)
		}()
	}
}

func (t *Tunnel) relay(ctx context.Context, local net.Conn, target string) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	remote, err := t.dial(dialCtx, target)
	cancel()
	if err != nil {
		_ = local.Close()
		return
	}
	netrelay.Relay(ctx, local, remote, netrelay.Options{})
}

type peerInfo struct {
	ip        string
	connected bool
}

func (t *Tunnel) clientPeers() ([]peerInfo, error) {
	status, err := t.client.Status()
	if err != nil {
		return nil, fmt.Errorf("embedded netbird status: %w", err)
	}
	out := make([]peerInfo, 0, len(status.Peers))
	for _, p := range status.Peers {
		out = append(out, peerInfo{ip: p.IP, connected: p.ConnStatus == netbird.PeerStatusConnected})
	}
	return out, nil
}

func waitForPeer(ctx context.Context, ip netip.Addr, peers func() ([]peerInfo, error)) error {
	ticker := time.NewTicker(peerPoll)
	defer ticker.Stop()
	for {
		list, err := peers()
		if err != nil {
			return err
		}
		known := false
		for _, p := range list {
			if !sameAddr(p.ip, ip) {
				continue
			}
			known = true
			if p.connected {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			if !known {
				return fmt.Errorf("%s is not in this device's NetBird network map; check that the machine is in the same mesh in the Brev dashboard", ip)
			}
			return fmt.Errorf("%s is in the network map but its tunnel did not come up: %w", ip, ctx.Err())
		case <-ticker.C:
		}
	}
}

// sameAddr compares a status entry, which may carry a prefix length, with ip.
func sameAddr(entry string, ip netip.Addr) bool {
	entry = strings.TrimSpace(entry)
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		return prefix.Addr().Unmap() == ip.Unmap()
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return false
	}
	return addr.Unmap() == ip.Unmap()
}

type clientOptions struct {
	deviceName    string
	managementURL string
	setupKey      string
	privateKey    string
}

func newClient(dir string, o clientOptions, logW io.Writer) (*netbird.Client, error) {
	// The NAT port mapper probes the LAN over UPnP and NAT-PMP, which an
	// outbound-only session on a laptop has no use for.
	if os.Getenv(envDisableNATMapper) == "" {
		if err := os.Setenv(envDisableNATMapper, "true"); err != nil {
			return nil, fmt.Errorf("set %s: %w", envDisableNATMapper, err)
		}
	}
	lazy := false
	randomPort := 0
	client, err := netbird.New(netbird.Options{
		DeviceName:            o.deviceName,
		SetupKey:              o.setupKey,
		PrivateKey:            o.privateKey,
		ManagementURL:         o.managementURL,
		ConfigPath:            filepath.Join(dir, configFile),
		StatePath:             filepath.Join(dir, stateFile),
		LogOutput:             logW,
		LogLevel:              "warn",
		BlockInbound:          true,
		DisableClientRoutes:   true,
		LazyConnectionEnabled: &lazy,
		WireguardPort:         &randomPort,
	})
	if err != nil {
		return nil, fmt.Errorf("create embedded netbird client: %w", err)
	}
	return client, nil
}

// startBounded wraps Start with a deadline of its own, because embed.Start
// only honors ctx once the management login has completed.
func startBounded(ctx context.Context, client *netbird.Client) error {
	ctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- client.Start(ctx) }()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("start embedded netbird client: %w", err)
		}
		return nil
	case <-ctx.Done():
		go func() {
			if err := <-errCh; err == nil {
				stopClient(client)
			}
		}()
		return fmt.Errorf("start embedded netbird client: %w", ctx.Err())
	}
}

func stopClient(client *netbird.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()
	_ = client.Stop(ctx)
}

func openLog(dir string) (io.Writer, func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, logFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open tunnel log: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}

func readIdentity(dir string) (Identity, error) {
	var id Identity
	data, err := os.ReadFile(filepath.Join(dir, identityFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return id, ErrNotRegistered
		}
		return id, fmt.Errorf("read tunnel identity: %w", err)
	}
	if err := json.Unmarshal(data, &id); err != nil {
		return id, fmt.Errorf("parse tunnel identity: %w", err)
	}
	if id.ManagementURL == "" {
		return id, ErrNotRegistered
	}
	return id, nil
}

// readPrivateKey pulls the WireGuard private key out of the netbird config
// the embed package persisted, so later sessions can log in without a setup key.
func readPrivateKey(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotRegistered
		}
		return "", fmt.Errorf("read netbird config: %w", err)
	}
	var cfg struct {
		PrivateKey string
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("parse netbird config: %w", err)
	}
	if cfg.PrivateKey == "" {
		return "", ErrNotRegistered
	}
	return cfg.PrivateKey, nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
