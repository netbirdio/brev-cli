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
	"strconv"
	"time"

	"github.com/netbirdio/netbird/util/netrelay"
	"github.com/spf13/cobra"

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
				return fmt.Errorf("invalid port %q: %w", args[1], err)
			}
			return run(cmd.Context(), args[0], uint16(port))
		},
	}
}

func run(ctx context.Context, host string, port uint16) error {
	// The tunnel redirects os.Stderr into its log while the engine runs; keep
	// the real one so progress and errors still reach the user through ssh.
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
// relay unwrapped. Close really closes both ends: when the overlay side goes
// away first, closing stdout hands ssh its EOF and closing stdin unblocks the
// pending read, so the ProxyCommand exits instead of hanging.
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
