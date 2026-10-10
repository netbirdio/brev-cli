// Package nbtunnel runs the NetBird client embedded in brev-cli so a device can
// reach Brev machines over the NetBird overlay without installing the netbird
// daemon. The peer identity lives under ~/.brev/netbird: brev register creates
// it once from the setup key in Brev's registration command, and the nb-proxy
// ProxyCommand behind brev ssh --netbird starts it for the length of a session.
package nbtunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	netbird "github.com/netbirdio/netbird/client/embed"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	startGrace   = 15 * time.Second
	stopTimeout  = 5 * time.Second
	peerPoll     = time.Second

	envDisableNATMapper = "NB_DISABLE_NAT_MAPPER"
)

var (
	// ErrNotRegistered means no embedded tunnel identity exists on this device.
	ErrNotRegistered = errors.New("the embedded Brev tunnel is not set up on this device; run 'brev register --embedded' first")
	// ErrLocked means another brev process is already running the embedded peer.
	ErrLocked = errors.New("another brev command is already using the embedded Brev tunnel; wait for it to finish")
	// ErrIdentityRejected means management no longer accepts this device's key,
	// usually because the device was removed from Brev.
	ErrIdentityRejected = errors.New("this device's tunnel identity is no longer known to Brev; run 'brev deregister' and then 'brev register --embedded' again")
)

// Dir returns the directory holding the embedded tunnel identity for userHome.
func Dir(userHome string) string {
	return filepath.Join(files.GetBrevHome(userHome), dirName)
}

// Identity is what brev register persists once enrollment has succeeded. The
// WireGuard private key stays in the netbird config file next to it.
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

// Register enrolls the device by logging in to management once with the setup
// key, then stops the client and persists the identity. The setup key itself is
// never written to disk; later sessions log in with the persisted private key.
//
// A private key left behind by an earlier attempt is reused rather than
// replaced: management logs a key it already knows straight in and only
// registers it with the setup key when it does not, so a retry neither spends
// the key twice nor leaks a peer. Only a different management URL, meaning a
// different control plane, starts from a fresh key.
func Register(ctx context.Context, dir, deviceName string, creds Credentials) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	sess, err := openSession(dir)
	if err != nil {
		return err
	}
	defer sess.close()

	if err := discardForeignIdentity(dir, creds.ManagementURL); err != nil {
		return err
	}

	client, err := newClient(dir, clientOptions{
		deviceName:    deviceName,
		managementURL: creds.ManagementURL,
		setupKey:      creds.SetupKey,
	}, sess.logFile)
	if err != nil {
		return err
	}
	if err := checkManagementURL(client, creds.ManagementURL); err != nil {
		return err
	}
	if err := startBounded(ctx, client); err != nil {
		return err
	}
	stopClient(client)

	return writeJSON(filepath.Join(dir, identityFile), Identity{
		DeviceName:    deviceName,
		ManagementURL: creds.ManagementURL,
		RegisteredAt:  time.Now().UTC().Format(time.RFC3339),
	})
}

// discardForeignIdentity removes a persisted key and state that belong to
// another management server, so the setup key enrolls a fresh peer there.
func discardForeignIdentity(dir, managementURL string) error {
	existing, err := readConfigManagementURL(dir)
	if err != nil || existing == "" || sameManagementURL(existing, managementURL) {
		return nil
	}
	for _, name := range []string{identityFile, configFile, stateFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale %s: %w", name, err)
		}
	}
	return nil
}

// Tunnel is the embedded peer for one brev session.
type Tunnel struct {
	id     Identity
	client *netbird.Client
	dial   func(ctx context.Context, addr string) (net.Conn, error)
	peers  func() ([]peerInfo, error)
	sess   *session

	mu      sync.Mutex
	started bool
	closed  bool
}

// Open loads the identity under dir and prepares the client. It does not
// connect; call Start. From Open until Close, os.Stderr and the global logrus
// output point at the tunnel log, see session.
func Open(dir string) (*Tunnel, error) {
	id, err := readIdentity(dir)
	if err != nil {
		return nil, err
	}
	privateKey, err := readPrivateKey(dir)
	if err != nil {
		return nil, err
	}
	sess, err := openSession(dir)
	if err != nil {
		return nil, err
	}
	client, err := newClient(dir, clientOptions{
		deviceName:    id.DeviceName,
		managementURL: id.ManagementURL,
		privateKey:    privateKey,
	}, sess.logFile)
	if err != nil {
		sess.close()
		return nil, err
	}
	if err := checkManagementURL(client, id.ManagementURL); err != nil {
		sess.close()
		return nil, err
	}

	t := &Tunnel{id: id, client: client, sess: sess}
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

// LogPath returns the file the embedded client logs to.
func (t *Tunnel) LogPath() string {
	return t.sess.logFile.Name()
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

// Close stops the embedded client, restores stderr and logging, and releases
// the identity lock. It is safe to call more than once.
func (t *Tunnel) Close() {
	t.mu.Lock()
	started, closed := t.started, t.closed
	t.started, t.closed = false, true
	t.mu.Unlock()
	if closed {
		return
	}
	if started {
		stopClient(t.client)
	}
	if t.sess != nil {
		t.sess.close()
	}
}

type peerInfo struct {
	ip        string
	connected bool
}

func (t *Tunnel) clientPeers() ([]peerInfo, error) {
	st, err := t.client.Status()
	if err != nil {
		return nil, fmt.Errorf("embedded netbird status: %w", err)
	}
	out := make([]peerInfo, 0, len(st.Peers))
	for _, p := range st.Peers {
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

// session owns the log file and the redirections that keep engine output off
// the terminal for as long as an engine runs: embed.New points the global
// logrus at its LogOutput, and pion writes ICE errors straight to os.Stderr,
// which an ssh holding the terminal in raw mode would garble.
type session struct {
	unlock     func()
	logFile    *os.File
	prevStderr *os.File
}

func openSession(dir string) (*session, error) {
	unlock, err := lock(dir)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, logFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		unlock()
		return nil, fmt.Errorf("open tunnel log: %w", err)
	}
	s := &session{unlock: unlock, logFile: f, prevStderr: os.Stderr}
	os.Stderr = f
	return s, nil
}

// close restores stderr, then points logrus away from the file before closing
// it, because engine goroutines can outlive Stop and would otherwise report a
// closed log on the terminal.
func (s *session) close() {
	os.Stderr = s.prevStderr
	logrus.SetOutput(io.Discard)
	_ = s.logFile.Close()
	s.unlock()
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

// checkManagementURL refuses to run when a NetBird MDM policy on this machine
// has replaced the management URL Brev handed out, since the embedded peer
// would then enroll with the wrong control plane.
func checkManagementURL(client *netbird.Client, want string) error {
	cfg, err := client.GetConfig()
	if err != nil {
		return fmt.Errorf("read embedded netbird config: %w", err)
	}
	if cfg.ManagementURL == nil || sameManagementURL(cfg.ManagementURL.String(), want) {
		return nil
	}
	return fmt.Errorf("a NetBird policy on this machine forces the management URL %s, which is not Brev's %s; the embedded Brev tunnel cannot be used here", cfg.ManagementURL, want)
}

// sameManagementURL compares two management URLs by scheme and host, treating
// an omitted :443 as present.
func sameManagementURL(a, b string) bool {
	return canonicalURL(a) == canonicalURL(b)
}

func canonicalURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	host := strings.ToLower(u.Host)
	if u.Port() == "" && u.Scheme == "https" {
		host += ":443"
	}
	return strings.ToLower(u.Scheme) + "://" + host
}

// startBounded wraps Start with a deadline of its own, because embed.Start
// only honors ctx once the management login has completed. On a timeout the
// orphaned Start is given a short grace to return before the caller tears the
// log and lock down underneath it.
func startBounded(ctx context.Context, client *netbird.Client) error {
	ctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- client.Start(ctx) }()

	select {
	case err := <-errCh:
		if err != nil {
			return startError(err)
		}
		return nil
	case <-ctx.Done():
	}

	select {
	case err := <-errCh:
		if err == nil {
			stopClient(client)
		}
	case <-time.After(startGrace):
		go func() {
			if err := <-errCh; err == nil {
				stopClient(client)
			}
		}()
	}
	return fmt.Errorf("start embedded netbird client: %w", ctx.Err())
}

// startError turns a management refusal of the persisted key into the
// actionable ErrIdentityRejected, keeping the raw error attached.
func startError(err error) error {
	switch grpcCode(err) {
	case codes.PermissionDenied, codes.Unauthenticated, codes.InvalidArgument, codes.NotFound:
		return fmt.Errorf("%w: %v", ErrIdentityRejected, err)
	default:
		return fmt.Errorf("start embedded netbird client: %w", err)
	}
}

func grpcCode(err error) codes.Code {
	var withStatus interface{ GRPCStatus() *status.Status }
	if errors.As(err, &withStatus) && withStatus.GRPCStatus() != nil {
		return withStatus.GRPCStatus().Code()
	}
	return codes.Unknown
}

func stopClient(client *netbird.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()
	_ = client.Stop(ctx)
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

// persistedConfig is the slice of netbird's profile config this package reads
// back: the private key for later logins and the management URL to detect a
// change of control plane. The key field has no json tag upstream.
type persistedConfig struct {
	PrivateKey    string
	ManagementURL *url.URL
}

func readConfig(dir string) (persistedConfig, error) {
	var cfg persistedConfig
	data, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, ErrNotRegistered
		}
		return cfg, fmt.Errorf("read netbird config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse netbird config: %w", err)
	}
	return cfg, nil
}

// readPrivateKey pulls the WireGuard private key out of the netbird config
// the embed package persisted, so later sessions can log in without a setup key.
func readPrivateKey(dir string) (string, error) {
	cfg, err := readConfig(dir)
	if err != nil {
		return "", err
	}
	if cfg.PrivateKey == "" {
		return "", ErrNotRegistered
	}
	return cfg.PrivateKey, nil
}

func readConfigManagementURL(dir string) (string, error) {
	cfg, err := readConfig(dir)
	if err != nil {
		return "", err
	}
	if cfg.ManagementURL == nil {
		return "", nil
	}
	return cfg.ManagementURL.String(), nil
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
