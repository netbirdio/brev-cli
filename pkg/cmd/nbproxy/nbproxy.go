// Package nbproxy implements the hidden `brev nb-proxy <host> <port>` command
// for use as an OpenSSH ProxyCommand: it starts the embedded Brev tunnel,
// dials host:port over the NetBird overlay and relays stdin/stdout. It shares
// the identity that `brev register --embedded` created, so an ssh_config entry
// can reach the overlay without going through `brev ssh --netbird`.
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
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("user home dir: %w", err)
	}
	tunnel, err := nbtunnel.Open(nbtunnel.Dir(home))
	if err != nil {
		return err //nolint:wrapcheck // the tunnel errors already name the remedy
	}
	defer tunnel.Close()

	startCtx, cancel := context.WithTimeout(ctx, startTimeout)
	err = tunnel.Start(startCtx)
	cancel()
	if err != nil {
		return err //nolint:wrapcheck // already wrapped by the tunnel
	}

	if addr, perr := netip.ParseAddr(host); perr == nil {
		waitCtx, cancel := context.WithTimeout(ctx, peerTimeout)
		err = tunnel.WaitForPeer(waitCtx, addr)
		cancel()
		if err != nil {
			return err //nolint:wrapcheck // already wrapped by the tunnel
		}
	}

	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	conn, err := tunnel.Dial(dialCtx, target)
	cancel()
	if err != nil {
		return fmt.Errorf("dial %s over netbird: %w", target, err)
	}

	netrelay.Relay(ctx, &stdioConn{Reader: os.Stdin, Writer: os.Stdout}, conn, netrelay.Options{})
	return nil
}

// stdioConn presents the process stdio as one closable stream for the relay.
// Read and Write are promoted from the embedded fields so io.EOF reaches the
// relay unwrapped.
type stdioConn struct {
	io.Reader
	io.Writer
}

func (*stdioConn) Close() error { return nil }
