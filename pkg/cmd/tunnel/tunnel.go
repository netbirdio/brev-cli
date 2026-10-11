// Package tunnel implements `brev tunnel`, which inspects the NetBird client
// embedded in brev: `brev tunnel status` brings the peer up, waits for its
// NetBird address and prints the management, signal and peer state, so the
// enrollment made by `brev register --embedded` can be checked against the
// Brev console.
package tunnel

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	breverrors "github.com/brevdev/brev-cli/pkg/errors"
	"github.com/brevdev/brev-cli/pkg/nbtunnel"
)

const (
	startTimeout = 60 * time.Second
	joinTimeout  = 60 * time.Second
	refresh      = 3 * time.Second
)

// NewCmdTunnel returns the `brev tunnel` command group.
func NewCmdTunnel() *cobra.Command {
	cmd := &cobra.Command{
		Annotations:           map[string]string{"configuration": ""},
		Use:                   "tunnel",
		DisableFlagsInUseLine: true,
		Short:                 "Inspect the embedded Brev tunnel (NetBird)",
		Long: `Inspect the NetBird client embedded in brev, as set up by 'brev register --embedded'.

'brev tunnel status' starts the embedded peer, waits until Brev's NetBird
management has accepted it and assigned a NetBird IP, and prints that address
together with the peers in its network map and their connection state.`,
		Example: `  # Connect, print the NetBird IP and the peer table, then disconnect
  brev tunnel status

  # Stay connected for five minutes so the device shows up as connected in Brev
  brev tunnel status --keep 5m`,
	}
	cmd.AddCommand(newCmdStatus())
	return cmd
}

func newCmdStatus() *cobra.Command {
	var keep time.Duration
	cmd := &cobra.Command{
		Annotations:           map[string]string{"configuration": ""},
		Use:                   "status",
		DisableFlagsInUseLine: true,
		Short:                 "Bring the embedded tunnel up and show its NetBird address and peers",
		Args:                  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd.Context(), keep)
		},
	}
	cmd.Flags().DurationVar(&keep, "keep", 0, "stay connected this long after the first report, reprinting the peers when they change (for example 5m); Ctrl-C stops earlier")
	return cmd
}

func runStatus(ctx context.Context, keep time.Duration) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The tunnel redirects os.Stderr into its log while the engine runs; keep
	// the real one for progress.
	stderr := os.Stderr
	home, err := os.UserHomeDir()
	if err != nil {
		return breverrors.WrapAndTrace(err)
	}
	dir := nbtunnel.Dir(home)
	if !nbtunnel.IsRegistered(dir) {
		return breverrors.NewValidationError(nbtunnel.ErrNotRegistered.Error())
	}
	tunnel, err := nbtunnel.Open(dir)
	if err != nil {
		return breverrors.NewValidationError(err.Error())
	}
	defer tunnel.Close()

	id := tunnel.Identity()
	fmt.Fprintf(stderr, "Starting the embedded Brev tunnel as %s against %s ...\n", id.DeviceName, id.ManagementURL)
	startCtx, cancel := context.WithTimeout(ctx, startTimeout)
	err = tunnel.Start(startCtx)
	cancel()
	if err != nil {
		return breverrors.NewValidationError(fmt.Sprintf("%v (details in %s)", err, tunnel.LogPath()))
	}

	fmt.Fprintln(stderr, "Waiting for a NetBird address ...")
	joinCtx, cancel := context.WithTimeout(ctx, joinTimeout)
	st, joinErr := tunnel.WaitForIP(joinCtx)
	cancel()
	fmt.Fprint(os.Stdout, st.Format(time.Now()))
	if joinErr != nil {
		return breverrors.NewValidationError(fmt.Sprintf("%v (details in %s)", joinErr, tunnel.LogPath()))
	}

	if keep > 0 {
		fmt.Fprintf(stderr, "\nStaying connected for %s; the peer table is reprinted when it changes. Ctrl-C to stop.\n", keep)
		watchPeers(ctx, stderr, tunnel, keep, st)
	}
	return nil
}

// watchPeers keeps the peer online and reprints the peer table whenever a
// peer's state changes, until keep elapses or ctx is canceled.
func watchPeers(ctx context.Context, out io.Writer, tunnel *nbtunnel.Tunnel, keep time.Duration, last nbtunnel.Status) {
	deadline := time.NewTimer(keep)
	defer deadline.Stop()
	ticker := time.NewTicker(refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-ticker.C:
			st, err := tunnel.Status()
			if err != nil {
				fmt.Fprintf(out, "status: %v\n", err)
				continue
			}
			if peerSummary(st) == peerSummary(last) {
				continue
			}
			last = st
			fmt.Fprintf(out, "\n%s\n%s", time.Now().Format(time.TimeOnly), st.FormatPeers(time.Now()))
		}
	}
}

func peerSummary(st nbtunnel.Status) string {
	var s string
	for _, p := range st.Peers {
		s += p.PubKey + ":" + p.Status + ":" + fmt.Sprint(p.Relayed) + "\n"
	}
	return s
}
