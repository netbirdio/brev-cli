// Package nbproxy carries an OpenSSH byte stream through the NetBird helper.
package nbproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/brevdev/brev-cli/pkg/nbembed"
	"github.com/spf13/cobra"
)

type proxyDeps struct {
	defaultDir func() (string, error)
	dial       func(context.Context, string, string) (net.Conn, error)
}

// NewCmdNBProxy constructs the byte-clean OpenSSH ProxyCommand entry point.
func NewCmdNBProxy() *cobra.Command {
	return newCmdNBProxy(proxyDeps{nbembed.DefaultDir, nbembed.Dial})
}

func newCmdNBProxy(deps proxyDeps) *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:                "nb-proxy <target-id>",
		Short:              "Carry an SSH connection through NetBird",
		Hidden:             true,
		Args:               cobra.ExactArgs(1),
		SilenceUsage:       true,
		SilenceErrors:      true,
		PersistentPreRunE:  func(*cobra.Command, []string) error { return nil },
		PersistentPostRunE: func(*cobra.Command, []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" {
				var err error
				dir, err = deps.defaultDir()
				if err != nil {
					return fmt.Errorf("cannot resolve NetBird state directory: %w", err)
				}
			}
			dialCtx, cancel := context.WithTimeout(cmd.Context(), 55*time.Second)
			conn, err := deps.dial(dialCtx, dir, args[0])
			cancel()
			if err != nil {
				return fmt.Errorf("NetBird connection failed: %w", err)
			}
			defer conn.Close()
			return forward(cmd.Context(), conn, cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dir, "state-dir", "", "private transport state directory")
	return cmd
}

// forward never prints on stdout, which is reserved for SSH packets. A remote
// EOF ends the proxy even when the local stdin reader is still blocked.
func forward(ctx context.Context, conn net.Conn, stdin io.Reader, stdout io.Writer) error {
	inputDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, stdin)
		if half, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		inputDone <- err
	}()
	outputDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(stdout, conn)
		outputDone <- err
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-outputDone:
			return err
		case err := <-inputDone:
			if err != nil {
				return err
			}
			inputDone = nil
		}
	}
}
