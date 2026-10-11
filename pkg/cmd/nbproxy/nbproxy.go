// Package nbproxy implements the hidden `brev nb-proxy <host> <port>` command,
// the OpenSSH ProxyCommand behind `brev ssh --netbird`: it starts the embedded
// Brev tunnel, waits for the target peer, dials host:port over the NetBird
// overlay and relays stdin/stdout for the length of the session. Keeping the
// overlay hop in a ProxyCommand leaves the ssh_config alias untouched, so the
// `Match host <alias> exec "brev mint-cert ..."` block, the user and agent
// forwarding keep applying.
package nbproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/netbirdio/netbird/util/netrelay"
	"github.com/spf13/cobra"

	tunnelcmd "github.com/brevdev/brev-cli/pkg/cmd/tunnel"
	breverrors "github.com/brevdev/brev-cli/pkg/errors"
	"github.com/brevdev/brev-cli/pkg/externalnode"
	"github.com/brevdev/brev-cli/pkg/nbtunnel"
)

const (
	startTimeout = 60 * time.Second
	peerTimeout  = 25 * time.Second
	dialTimeout  = 20 * time.Second
)

// NewCmdNBProxy returns the hidden ProxyCommand backend. store supplies the
// Brev session that unlocks the tunnel identity; it must not start an
// interactive login, since stdio belongs to ssh here.
func NewCmdNBProxy(store externalnode.TokenProvider) *cobra.Command {
	return &cobra.Command{
		Annotations:           map[string]string{"hidden": ""},
		Hidden:                true,
		Use:                   "nb-proxy <host> <port>",
		Short:                 "ssh ProxyCommand over the embedded Brev tunnel",
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			port, err := strconv.ParseUint(args[1], 10, 16)
			if err != nil {
				return breverrors.NewValidationError(fmt.Sprintf("invalid port %q", args[1]))
			}
			// Every failure here is a tunnel condition the user can act on, not
			// a crash: report it plainly and keep it out of error telemetry.
			if err := run(cmd.Context(), store, args[0], uint16(port)); err != nil {
				return breverrors.NewValidationError("Brev tunnel: " + err.Error())
			}
			return nil
		},
	}
}

func run(ctx context.Context, store externalnode.TokenProvider, host string, port uint16) error {
	// ssh ends the session by closing our pipes and sending SIGHUP; turn that
	// into a context cancel so the relay returns and the engine is stopped.
	// A write to a pipe ssh already closed must surface as EPIPE, not kill us.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	signal.Ignore(syscall.SIGPIPE)

	// The tunnel redirects os.Stderr into its log while the engine runs; keep
	// the real one so progress still reaches the user through ssh.
	stderr := os.Stderr
	clock := newStopwatch()
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("user home dir: %w", err)
	}
	progressf(stderr, "%sunlocking the Brev tunnel identity", clock.stamp())
	tunnel, err := openTunnel(ctx, store, nbtunnel.Dir(home))
	if err != nil {
		return err //nolint:wrapcheck // the tunnel errors already name the remedy
	}
	defer tunnel.Close()
	unlock := clock.lap()

	progressf(stderr, "%sstarting the Brev tunnel", clock.stamp())
	startCtx, cancel := context.WithTimeout(ctx, startTimeout)
	err = tunnel.Start(startCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("%w (details in %s)", err, tunnel.LogPath())
	}
	engine := clock.lap()

	link := "unknown"
	var peerWait time.Duration
	if addr, perr := netip.ParseAddr(host); perr == nil {
		progressf(stderr, "%swaiting for %s to connect over NetBird", clock.stamp(), host)
		waitCtx, cancel := context.WithTimeout(ctx, peerTimeout)
		err = tunnel.WaitForPeer(waitCtx, addr)
		cancel()
		if err != nil {
			return err //nolint:wrapcheck // already names the cause
		}
		peerWait = clock.lap()
		if p, ok := tunnel.PeerLink(addr); ok {
			link = p.LinkWord()
			if p.Latency > 0 {
				link += fmt.Sprintf(", latency %s", p.Latency.Round(time.Millisecond))
			}
		}
		if clock.timing {
			progressf(stderr, "%speer %s connected via %s", clock.stamp(), host, link)
		}
	}

	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	conn, err := tunnel.Dial(dialCtx, target)
	cancel()
	if err != nil {
		return fmt.Errorf("dial %s over netbird: %w", target, err)
	}
	dial := clock.lap()
	summary := fmt.Sprintf("connected to %s over NetBird after %s (unlock %s, engine start %s, peer connect %s via %s, dial %s)",
		target, clock, fmtDur(unlock), fmtDur(engine), fmtDur(peerWait), link, fmtDur(dial))
	// os.Stderr is the tunnel log while the engine runs; the breakdown always
	// lands there, next to the engine's own timestamps.
	progressf(os.Stderr, "timing: %s", summary)
	if !clock.timing {
		progressf(stderr, "connected to %s over NetBird", target)
		netrelay.Relay(ctx, newStdioConn(), conn, netrelay.Options{})
		return nil
	}
	progressf(stderr, "%s%s", clock.stamp(), summary)
	// The first bytes back are sshd's banner: from here on the overlay path
	// carries the session and what remains is the ssh handshake itself.
	remote := &firstByteConn{Conn: conn, onFirst: func(n int) {
		progressf(stderr, "%sfirst %d bytes from %s (sshd banner); the ssh handshake runs from here", clock.stamp(), n, target)
	}}
	netrelay.Relay(ctx, newStdioConn(), remote, netrelay.Options{})
	return nil
}

// openTunnel unlocks the identity with the credentials the parent brev ssh
// left in the environment, or fetches them itself when nb-proxy runs alone.
func openTunnel(ctx context.Context, store externalnode.TokenProvider, dir string) (*nbtunnel.Tunnel, error) {
	creds, ok, err := tunnelcmd.CredentialsFromEnv()
	if err != nil {
		return nil, err //nolint:wrapcheck // names the variable already
	}
	if ok {
		return nbtunnel.Open(dir, creds) //nolint:wrapcheck // names the remedy already
	}
	return tunnelcmd.Open(ctx, store, dir) //nolint:wrapcheck // names the remedy already
}

// stopwatch measures the laps between the connection phases and, when the
// user asked for timing, stamps progress lines with the time since start.
type stopwatch struct {
	start  time.Time
	last   time.Time
	timing bool
}

func newStopwatch() *stopwatch {
	now := time.Now()
	return &stopwatch{start: now, last: now, timing: nbtunnel.TimingEnabled()}
}

// stamp is the "[+1.20s] " prefix of a progress line, or nothing.
func (s *stopwatch) stamp() string {
	if !s.timing {
		return ""
	}
	return "[" + s.String() + "] "
}

// lap returns the time since the previous lap (or the start).
func (s *stopwatch) lap() time.Duration {
	now := time.Now()
	d := now.Sub(s.last)
	s.last = now
	return d
}

func (s *stopwatch) String() string {
	return "+" + fmtDur(time.Since(s.start))
}

func fmtDur(d time.Duration) string {
	return d.Round(10 * time.Millisecond).String()
}

// firstByteConn reports the first successful read from the remote once.
type firstByteConn struct {
	net.Conn
	once    sync.Once
	onFirst func(n int)
}

func (c *firstByteConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.once.Do(func() { c.onFirst(n) })
	}
	return n, err //nolint:wrapcheck // io.EOF must reach the relay unwrapped
}

func progressf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, "brev: "+format+"\n", args...)
}

// stdioConn presents the process stdio as one closable stream for the relay.
// Read and Write are promoted from the embedded fields so io.EOF reaches the
// relay unwrapped. Close closes stdout so ssh sees EOF when the overlay side
// goes away first; the stdin read ends when ssh closes its end of the pipe or
// signals us, which the context above turns into a relay cancel.
type stdioConn struct {
	io.Reader
	io.Writer
	in  *os.File
	out *os.File
}

func newStdioConn() *stdioConn {
	return &stdioConn{Reader: os.Stdin, Writer: os.Stdout, in: os.Stdin, out: os.Stdout}
}

func (s *stdioConn) Close() error {
	_ = s.out.Close()
	_ = s.in.Close()
	return nil
}
