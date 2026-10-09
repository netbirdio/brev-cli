// Package nbproxy implements the hidden `brev nb-proxy <host> <port>` command
// used as an OpenSSH ProxyCommand: it brings up an embedded NetBird peer in
// netstack mode, dials host:port over the overlay and relays stdin/stdout.
package nbproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	netbird "github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/util/netrelay"
	"github.com/spf13/cobra"
)

const (
	startTimeout = 20 * time.Second
	dialTimeout  = 20 * time.Second
	stopTimeout  = 5 * time.Second
)

// credentials is what `brev refresh` persists under ~/.brev/netbird/credentials.json.
type credentials struct {
	ManagementURL string    `json:"managementUrl"`
	SetupKey      string    `json:"setupKey"`
	DeviceName    string    `json:"deviceName"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

// NewCmdNBProxy returns the hidden ProxyCommand backend.
func NewCmdNBProxy() *cobra.Command {
	return &cobra.Command{
		Annotations:           map[string]string{"hidden": ""},
		Hidden:                true,
		Use:                   "nb-proxy <host> <port>",
		Short:                 "ssh ProxyCommand over the embedded NetBird client",
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

func nbDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("user home dir: %w", err)
	}
	return filepath.Join(home, ".brev", "netbird"), nil
}

func loadCredentials(dir string) (credentials, error) {
	var c credentials
	b, err := os.ReadFile(filepath.Join(dir, "credentials.json"))
	if err != nil {
		return c, fmt.Errorf("read netbird credentials (run `brev refresh`): %w", err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse netbird credentials: %w", err)
	}
	if c.SetupKey == "" || c.ManagementURL == "" {
		return c, errors.New("netbird credentials incomplete (run `brev refresh`)")
	}
	return c, nil
}

func run(ctx context.Context, host string, port uint16) error {
	dir, err := nbDir()
	if err != nil {
		return err
	}
	cred, err := loadCredentials(dir)
	if err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(dir, "nb-proxy.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}
	defer logFile.Close() //nolint:errcheck // log file

	eager := false
	randomPort := 0
	nb, err := netbird.New(netbird.Options{
		DeviceName:            cred.DeviceName,
		SetupKey:              cred.SetupKey,
		ManagementURL:         cred.ManagementURL,
		LogOutput:             logFile,
		LogLevel:              "warn",
		BlockInbound:          true,
		LazyConnectionEnabled: &eager,
		WireguardPort:         &randomPort,
		StatePath:             filepath.Join(dir, "state.json"),
		// ConfigPath intentionally empty in the MVP: in-memory identity per
		// ProxyCommand process, paired with an Ephemeral setup key.
	})
	if err != nil {
		return fmt.Errorf("create embedded netbird client: %w", err)
	}

	if err := startBounded(ctx, nb); err != nil {
		return err
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), stopTimeout)
		defer cancel()
		_ = nb.Stop(stopCtx)
	}()

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	conn, err := nb.DialContext(dialCtx, "tcp", target)
	if err != nil {
		return fmt.Errorf("dial %s over netbird: %w", target, err)
	}

	netrelay.Relay(ctx, &stdioConn{Reader: os.Stdin, Writer: os.Stdout}, conn, netrelay.Options{})
	return nil
}

// startBounded wraps Start because embed.Start does not honor ctx during the
// management login phase (client/embed/embed.go:276-292).
func startBounded(ctx context.Context, nb *netbird.Client) error {
	errCh := make(chan error, 1)
	go func() { errCh <- nb.Start(ctx) }()
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("start embedded netbird client: %w", err)
		}
		return nil
	case <-time.After(startTimeout):
		return fmt.Errorf("start embedded netbird client: timeout after %s", startTimeout)
	}
}

// stdioConn presents the process stdio as one closable stream for the relay.
// Read and Write are promoted from the embedded fields so io.EOF reaches the
// relay unwrapped.
type stdioConn struct {
	io.Reader
	io.Writer
}

func (*stdioConn) Close() error { return nil }
