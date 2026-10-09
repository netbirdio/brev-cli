// Package nbembed wraps the embedded NetBird client so brev-cli can dial
// overlay addresses in-process, without a netbird daemon on the host.
package nbembed

import (
	"context"
	"fmt"
	"io"
	"net"

	netbird "github.com/netbirdio/netbird/client/embed"
)

// Options configures the embedded NetBird client.
type Options struct {
	DeviceName    string
	SetupKey      string
	ManagementURL string
	LogOutput     io.Writer
	LogLevel      string
}

// Client is a running embedded NetBird peer.
type Client struct {
	nb *netbird.Client
}

// New creates an embedded NetBird client in netstack mode. It does not
// connect until Start is called.
func New(opts Options) (*Client, error) {
	eager := false
	nb, err := netbird.New(netbird.Options{
		DeviceName:            opts.DeviceName,
		SetupKey:              opts.SetupKey,
		ManagementURL:         opts.ManagementURL,
		LogOutput:             opts.LogOutput,
		LogLevel:              opts.LogLevel,
		LazyConnectionEnabled: &eager,
	})
	if err != nil {
		return nil, fmt.Errorf("create embedded netbird client: %w", err)
	}
	return &Client{nb: nb}, nil
}

// Start logs in to management and brings up the overlay.
func (c *Client) Start(ctx context.Context) error {
	if err := c.nb.Start(ctx); err != nil {
		return fmt.Errorf("start embedded netbird client: %w", err)
	}
	return nil
}

// Stop tears the overlay down.
func (c *Client) Stop(ctx context.Context) error {
	if err := c.nb.Stop(ctx); err != nil {
		return fmt.Errorf("stop embedded netbird client: %w", err)
	}
	return nil
}

// Dial opens a TCP connection to an overlay address through the netstack.
func (c *Client) Dial(ctx context.Context, addr string) (net.Conn, error) {
	conn, err := c.nb.Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s over netbird: %w", addr, err)
	}
	return conn, nil
}

// VerifySSHHostKey checks an SSH host key against the peer's key from the
// network map.
func (c *Client) VerifySSHHostKey(peerAddr string, key []byte) error {
	if err := c.nb.VerifySSHHostKey(peerAddr, key); err != nil {
		return fmt.Errorf("verify ssh host key for %s: %w", peerAddr, err)
	}
	return nil
}
