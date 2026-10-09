package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/brevdev/brev-cli/pkg/analytics"
	"github.com/brevdev/brev-cli/pkg/cmd"
	"github.com/brevdev/brev-cli/pkg/cmd/cmderrors"
	"github.com/brevdev/brev-cli/pkg/cmd/nbagent"
	"github.com/brevdev/brev-cli/pkg/cmd/nbproxy"
	"github.com/brevdev/brev-cli/pkg/errors"
	"github.com/spf13/cobra"
)

func main() {
	// Proxy stdout is an SSH byte stream. Start the helper and proxy without
	// initializing login, analytics, version checks, or the error reporter.
	if len(os.Args) > 1 {
		var transportCommand *cobra.Command
		switch os.Args[1] {
		case "nb-agent":
			transportCommand = nbagent.NewCmdNBAgent()
		case "nb-proxy":
			transportCommand = nbproxy.NewCmdNBProxy()
		}
		if transportCommand != nil {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			transportCommand.SetContext(ctx)
			transportCommand.SetArgs(os.Args[2:])
			transportCommand.SilenceErrors = true
			transportCommand.SilenceUsage = true
			if err := transportCommand.Execute(); err != nil {
				_, _ = fmt.Fprintln(os.Stderr, "brev:", err)
				os.Exit(1)
			}
			return
		}
	}

	done := errors.GetDefaultErrorReporter().Setup()
	defer done()
	defer analytics.Close()
	command := cmd.NewDefaultBrevCommand()

	if err := command.Execute(); err != nil {
		analytics.CaptureCommandError()
		cmderrors.DisplayAndHandleError(err)
		done()
		os.Exit(1) //nolint:gocritic // manually call done
	}
}
