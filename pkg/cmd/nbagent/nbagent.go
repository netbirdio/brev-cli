// Package nbagent exposes the private, user-level NetBird helper entry point.
package nbagent

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/brevdev/brev-cli/pkg/nbembed"
	"github.com/spf13/cobra"
)

type agentDeps struct {
	defaultDir func() (string, error)
	enroll     func(context.Context, string, io.Reader) error
	serve      func(context.Context, string) error
}

// NewCmdNBAgent constructs the private helper entry point without login hooks.
func NewCmdNBAgent() *cobra.Command {
	return newCmdNBAgent(agentDeps{nbembed.DefaultDir, nbembed.RunEnrollment, nbembed.Serve})
}

func newCmdNBAgent(deps agentDeps) *cobra.Command {
	var dir string
	var enroll bool
	cmd := &cobra.Command{
		Use:                "nb-agent",
		Short:              "Run the private NetBird transport helper",
		Hidden:             true,
		Args:               cobra.NoArgs,
		SilenceUsage:       true,
		SilenceErrors:      true,
		PersistentPreRunE:  func(*cobra.Command, []string) error { return nil },
		PersistentPostRunE: func(*cobra.Command, []string) error { return nil },
		RunE: func(cmd *cobra.Command, _ []string) error {
			if enroll && os.Getenv("BREV_EXPERIMENTAL_NETBIRD") != "1" {
				return fmt.Errorf("NetBird enrollment requires BREV_EXPERIMENTAL_NETBIRD=1")
			}
			if dir == "" {
				var err error
				dir, err = deps.defaultDir()
				if err != nil {
					return fmt.Errorf("cannot resolve NetBird state directory")
				}
			}
			if enroll {
				if err := deps.enroll(cmd.Context(), dir, cmd.InOrStdin()); err != nil {
					// Never wrap enrollment errors: upstream errors may contain the setup key.
					return fmt.Errorf("NetBird enrollment failed; check management connectivity and the setup key")
				}
				return nil
			}
			return deps.serve(cmd.Context(), dir)
		},
	}
	cmd.Flags().StringVar(&dir, "state-dir", "", "private transport state directory")
	cmd.Flags().BoolVar(&enroll, "enroll", false, "read enrollment credentials from standard input")
	return cmd
}
