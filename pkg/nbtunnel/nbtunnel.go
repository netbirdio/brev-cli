// Package nbtunnel runs the NetBird client embedded in brev-cli so a device can
// reach Brev machines over the NetBird overlay without installing the netbird
// daemon. The peer identity lives under ~/.brev/netbird: brev register creates
// it once from the setup key in Brev's registration command and seals the
// peer's keys under that setup key, so every later start, such as the nb-proxy
// ProxyCommand behind brev ssh --netbird, first fetches the setup key again
// through Brev's API and therefore needs a valid Brev login.
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
	nbversion "github.com/netbirdio/netbird/version"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/brevdev/brev-cli/pkg/files"
)

const (
	dirName      = "netbird"
	identityFile = "tunnel.json"
	stateFile    = "state.json"
	logFile      = "tunnel.log"
	lockFile     = "lock"
	// legacyConfigFile is where earlier builds let the embedded client persist
	// its config, private key included; it is only ever removed now.
	legacyConfigFile = "config.json"

	startTimeout = 45 * time.Second
	startGrace   = 15 * time.Second
	joinTimeout  = 30 * time.Second
	stopTimeout  = 5 * time.Second
	peerPoll     = time.Second

	envDisableNATMapper = "NB_DISABLE_NAT_MAPPER"
	// EnvLogLevel overrides the embedded client's log level (default debug).
	EnvLogLevel     = "BREV_NETBIRD_LOG_LEVEL"
	defaultLogLevel = "debug"
)

var (
	// ErrNotRegistered means no embedded tunnel identity exists on this device.
	ErrNotRegistered = errors.New("the embedded Brev tunnel is not set up on this device; run 'brev register --embedded' first")
	// ErrLocked means another brev process is already running the embedded peer.
	ErrLocked = errors.New("another brev command is already using the embedded Brev tunnel; wait for it to finish")
	// ErrIdentityRejected means management no longer accepts this device's key,
	// usually because the device was removed from Brev.
	ErrIdentityRejected = errors.New("this device's tunnel identity is no longer known to Brev; run 'brev deregister' and then 'brev register --embedded' again")
	// ErrSetupKeyRejected means management refused the setup key Brev handed
	// out, for example because it was already used or has expired.
	ErrSetupKeyRejected = errors.New("Brev's tunnel setup key was refused; run 'brev deregister' and then 'brev register --embedded' again to get a new one")
	// ErrManagementInternal means management accepted the credentials but
	// failed on its own side; only its log says why.
	ErrManagementInternal = errors.New("Brev's NetBird management failed internally while handling this peer (the credentials were accepted up to that point); ask Brev to check the management log for 'got an unhandled error' at the time of this attempt")
)

// ClientVersion is the NetBird version the embedded client reports to
// management. It reads "development" unless the build set it.
func ClientVersion() string {
	return nbversion.NetbirdVersion()
}

// Dir returns the directory holding the embedded tunnel identity for userHome.
func Dir(userHome string) string {
	return filepath.Join(files.GetBrevHome(userHome), dirName)
}

// LogPath returns the embedded client's log file under dir.
func LogPath(dir string) string {
	return filepath.Join(dir, logFile)
}

// Remove deletes the identity, the netbird state and the log under dir.
func Remove(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove %s: %w", dir, err)
	}
	return nil
}

// CheckAvailable reports ErrLocked when another process is running the
// identity under dir, so a caller can fail fast before spawning ssh.
func CheckAvailable(dir string) error {
	unlock, err := lock(dir)
	if err != nil {
		return err
	}
	unlock()
	return nil
}

// Register enrolls the device as Brev node nodeID by logging in to management
// once with the setup key, waits for the peer to receive its NetBird address,
// then stops the client and persists the identity with the peer's keys sealed
// under that setup key. The returned Status shows what management handed out;
// Joined is false when the address did not arrive in time, in which case the
// enrollment is still kept. The client runs on an in-memory config, so neither
// the setup key nor a key in the clear is ever written to disk.
//
// When Brev's registration command names a hostname, the peer registers under
// it, exactly as the native netbird client would, so Brev can match the peer to
// the node it created.
//
// Every enrollment starts from a fresh key: a key an earlier attempt left
// behind can only be read back with the setup key of that attempt.
func Register(ctx context.Context, dir, nodeID, deviceName string, creds Credentials) (Status, error) {
	if creds.Hostname != "" {
		deviceName = creds.Hostname
	}
	if nodeID == "" {
		return Status{}, errors.New("register embedded tunnel: node id is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Status{}, fmt.Errorf("create %s: %w", dir, err)
	}
	sess, err := openSession(dir)
	if err != nil {
		return Status{}, err
	}
	defer sess.close()

	// The identity file marks a completed enrollment and is rewritten below;
	// without this a failed retry would leave it beside a key management never
	// accepted, and IsRegistered would report the device as enrolled.
	if err := clearIdentity(dir); err != nil {
		return Status{}, err
	}

	client, err := newClient(dir, clientOptions{
		deviceName:    deviceName,
		managementURL: creds.ManagementURL,
		setupKey:      creds.SetupKey,
	}, sess.logFile)
	if err != nil {
		return Status{}, err
	}
	if err := checkManagementURL(client, creds.ManagementURL); err != nil {
		return Status{}, err
	}
	fmt.Fprintf(sess.logFile, "brev: enrolling hostname=%q node=%s management=%s setup-key=%s client-version=%s at %s\n",
		deviceName, nodeID, creds.ManagementURL, creds.KeyFingerprint(), ClientVersion(), time.Now().UTC().Format(time.RFC3339))
	if err := startBounded(ctx, client, ErrSetupKeyRejected); err != nil {
		return Status{}, err
	}
	joinCtx, cancel := context.WithTimeout(ctx, joinTimeout)
	st, joinErr := waitForIP(joinCtx, func() (Status, error) { return statusOf(client, deviceName) })
	cancel()
	// The in-memory config holds the keys management now knows this peer by;
	// read them before Stop can release it.
	cfg, cfgErr := client.GetConfig()
	stopClient(client)
	if cfgErr != nil {
		return Status{}, fmt.Errorf("read enrolled keys: %w", cfgErr)
	}
	if joinErr != nil {
		// Start succeeded, so management knows the key; keep the identity and
		// let the caller report that the address has not arrived yet.
		st.ManagementError = joinErr.Error()
	}

	id := Identity{
		NodeID:        nodeID,
		DeviceName:    deviceName,
		ManagementURL: creds.ManagementURL,
		RegisteredAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := id.seal(secrets{PrivateKey: cfg.PrivateKey, SSHKey: cfg.SSHKey}, creds); err != nil {
		return st, fmt.Errorf("seal tunnel identity: %w", err)
	}
	if err := writeJSON(filepath.Join(dir, identityFile), id); err != nil {
		return st, err
	}
	return st, nil
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

// Open unlocks the identity under dir with the setup key Brev currently issues
// for its node and prepares the client. It does not connect; call Start. From
// Open until Close, os.Stderr and the global logrus output point at the tunnel
// log, see session.
//
// Only the WireGuard key is handed back to the client: the embed package has
// no option to install a stored SSH host key, so each start generates a fresh
// one, and the sealed copy waits for a client that can take it.
func Open(dir string, creds Credentials) (*Tunnel, error) {
	id, err := ReadIdentity(dir)
	if err != nil {
		return nil, err
	}
	keys, err := id.unseal(creds)
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
		privateKey:    keys.PrivateKey,
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
	if err := startBounded(ctx, t.client, ErrIdentityRejected); err != nil {
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
	// An empty ConfigPath keeps the config, keys included, in memory; only
	// the state file, which holds no secret, lands under dir.
	client, err := netbird.New(netbird.Options{
		DeviceName:            o.deviceName,
		SetupKey:              o.setupKey,
		PrivateKey:            o.privateKey,
		ManagementURL:         o.managementURL,
		StatePath:             filepath.Join(dir, stateFile),
		LogOutput:             logW,
		LogLevel:              logLevel(),
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

func logLevel() string {
	if level := os.Getenv(EnvLogLevel); level != "" {
		return level
	}
	return defaultLogLevel
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
// log and lock down underneath it; a refusal that lands in that window is
// still reported as such. refusal names what a management refusal means for
// the credential in use.
func startBounded(ctx context.Context, client *netbird.Client, refusal error) error {
	ctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- client.Start(ctx) }()

	select {
	case err := <-errCh:
		if err != nil {
			return startError(err, refusal)
		}
		return nil
	case <-ctx.Done():
	}

	select {
	case err := <-errCh:
		if err != nil {
			return startError(err, refusal)
		}
		stopClient(client)
	case <-time.After(startGrace):
		go func() {
			if err := <-errCh; err == nil {
				stopClient(client)
			}
		}()
	}
	return fmt.Errorf("start embedded netbird client: %w", ctx.Err())
}

// startError turns a management refusal into the actionable refusal error for
// the credential in use, keeping the raw error attached. An Internal code is
// management's catch-all for an unhandled error on its side, so it is named as
// such rather than blamed on the credential.
func startError(err, refusal error) error {
	switch grpcCode(err) {
	case codes.PermissionDenied, codes.Unauthenticated, codes.InvalidArgument, codes.NotFound, codes.FailedPrecondition:
		return fmt.Errorf("%w: %v", refusal, err)
	case codes.Internal:
		return fmt.Errorf("%w: %v", ErrManagementInternal, err)
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
