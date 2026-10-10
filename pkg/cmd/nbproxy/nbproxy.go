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
	"syscall"
	"time"

	"github.com/netbirdio/netbird/util/netrelay"
	"github.com/spf13/cobra"

	breverrors "github.com/brevdev/brev-cli/pkg/errors"
	"github.com/brevdev/brev-cli/pkg/nbtunnel"
)

const (
	startTimeout = 60 * time.Second
	peerTimeout  = 25 * time.Second
	dialTimeout  = 20 * time.Second
)

// NewCmdNBProxy returns the hidden ProxyCommand backend.
func NewCmdNBProxy() *cobra.Command {
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
			if err := run(cmd.Context(), args[0], uint16(port)); err != nil {
				return breverrors.NewValidationError("Brev tunnel: " + err.Error())
			}
			return nil
		},
	}
}

func run(ctx context.Context, host string, port uint16) error {
	// ssh ends the session by closing our pipes and sending SIGHUP; turn that
	// into a context cancel so the relay returns and the engine is stopped.
	// A write to a pipe ssh already closed must surface as EPIPE, not kill us.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	signal.Ignore(syscall.SIGPIPE)

	// The tunnel redirects os.Stderr into its log while the engine runs; keep
	// the real one so progress still reaches the user through ssh.
	stderr := os.Stderr
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("user home dir: %w", err)
	}
	tunnel, err := nbtunnel.Open(nbtunnel.Dir(home))
	if err != nil {
		return err //nolint:wrapcheck // the tunnel errors already name the remedy
	}
	defer tunnel.Close()

	progressf(stderr, "starting the Brev tunnel")
	startCtx, cancel := context.WithTimeout(ctx, startTimeout)
	err = tunnel.Start(startCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("%w (details in %s)", err, tunnel.LogPath())
	}

	if addr, perr := netip.ParseAddr(host); perr == nil {
		progressf(stderr, "waiting for %s to connect over NetBird", host)
		waitCtx, cancel := context.WithTimeout(ctx, peerTimeout)
		err = tunnel.WaitForPeer(waitCtx, addr)
		cancel()
		if err != nil {
			return err //nolint:wrapcheck // already names the cause
		}
	}

	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	conn, err := tunnel.Dial(dialCtx, target)
	cancel()
	if err != nil {
		return fmt.Errorf("dial %s over netbird: %w", target, err)
	}
	progressf(stderr, "connected to %s over NetBird", target)

	netrelay.Relay(ctx, newStdioConn(), conn, netrelay.Options{})
	return nil
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
