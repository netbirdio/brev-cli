// Package tunnel provides explicit onboarding for the experimental SSH transport.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/brevdev/brev-cli/pkg/nbembed"
	"github.com/brevdev/brev-cli/pkg/sshtransport"
	"github.com/spf13/cobra"
)

const experimentalEnv = "BREV_EXPERIMENTAL_NETBIRD"

type dependencies struct {
	defaultDir func() (string, error)
	enroll     func(context.Context, string, string, string, string) error
	readKeys   func(string) ([]string, error)
	configure  func(string, string, string, string, sshtransport.Target) error
	use        func(string, string) error
	mode       func(string) (string, error)
	status     func(context.Context, string) (nbembed.StatusInfo, error)
	stop       func(context.Context, string) error
	forget     func(context.Context, string) error
	paths      func(string) (string, string, string, error)
}

// NewCmdTunnel constructs explicit, local-only SSH pilot onboarding commands.
func NewCmdTunnel() *cobra.Command {
	return newCmdTunnel(dependencies{
		defaultDir: nbembed.DefaultDir,
		enroll:     nbembed.Enroll, readKeys: sshtransport.ReadHostKeys,
		configure: sshtransport.Configure, use: sshtransport.Use, mode: sshtransport.Mode,
		status: nbembed.Status, stop: nbembed.Stop, forget: nbembed.Forget,
		paths: configPaths,
	})
}

func configPaths(dir string) (string, string, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", "", err
	}
	exe, err := os.Executable()
	if err != nil {
		return "", "", "", err
	}
	return filepath.Join(home, ".ssh", "config"), filepath.Join(filepath.Dir(dir), "ssh_config"), exe, nil
}

func requireExperimental() error {
	if os.Getenv(experimentalEnv) != "1" {
		return fmt.Errorf("experimental NetBird SSH requires %s=1", experimentalEnv)
	}
	return nil
}

func newCmdTunnel(deps dependencies) *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use: "tunnel", Short: "Manage the experimental NetBird SSH transport",
		Long:               "Manage a local NetBird client identity for the SSH pilot. Enrollment uses an administrator-provided setup key; it does not register this computer as Brev compute.",
		Annotations:        map[string]string{"networking": ""},
		SilenceUsage:       true,
		PersistentPreRunE:  func(*cobra.Command, []string) error { return nil },
		PersistentPostRunE: func(*cobra.Command, []string) error { return nil },
	}
	cmd.PersistentFlags().StringVar(&dir, "state-dir", "", "private transport state directory")
	_ = cmd.PersistentFlags().MarkHidden("state-dir")
	resolveDir := func() (string, error) {
		if dir != "" {
			return dir, nil
		}
		return deps.defaultDir()
	}

	var managementURL, name string
	var keyStdin bool
	enroll := &cobra.Command{
		Use: "enroll --management-url URL --setup-key-stdin", Short: "Enroll this client with a setup key supplied on stdin",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireExperimental(); err != nil {
				return err
			}
			if !keyStdin {
				return fmt.Errorf("supply the setup key through stdin with --setup-key-stdin")
			}
			u, err := url.Parse(managementURL)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return fmt.Errorf("--management-url must be an HTTPS URL without credentials, a query, or a fragment")
			}
			stateDir, err := resolveDir()
			if err != nil {
				return err
			}
			status, err := deps.status(cmd.Context(), stateDir)
			if err != nil {
				return err
			}
			if status.Enrolled {
				return fmt.Errorf("this client is already enrolled; use 'brev tunnel status', or 'brev tunnel forget' before enrolling a new identity")
			}
			if name == "" {
				name, _ = os.Hostname()
				if strings.TrimSpace(name) == "" {
					name = "brev-client"
				}
			}
			if len(name) > 128 || strings.ContainsAny(name, "\r\n\x00") {
				return fmt.Errorf("device name must contain at most 128 characters without control characters")
			}
			keyBytes, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 4097))
			if err != nil {
				return fmt.Errorf("cannot read setup key from stdin")
			}
			if len(keyBytes) > 4096 {
				return fmt.Errorf("setup key exceeds the maximum input length")
			}
			key := strings.TrimSpace(string(keyBytes))
			if key == "" || strings.ContainsAny(key, " \t\r\n") {
				return fmt.Errorf("stdin must contain one setup key")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 50*time.Second)
			defer cancel()
			if err := deps.enroll(ctx, stateDir, managementURL, name, key); err != nil {
				// Upstream error strings can contain credentials; keep them out of
				// terminal output, analytics, and the global error reporter.
				return fmt.Errorf("NetBird enrollment failed; check management connectivity and the setup key")
			}
			cmd.Println("Client enrolled. Configure a target with a trusted SSH host key before selecting direct transport.")
			return nil
		},
	}
	enroll.Flags().StringVar(&managementURL, "management-url", "", "NetBird management HTTPS URL")
	enroll.Flags().StringVar(&name, "name", "", "device name shown in NetBird management")
	enroll.Flags().BoolVar(&keyStdin, "setup-key-stdin", false, "read the setup key from standard input")
	cmd.AddCommand(enroll)

	var address, keyFile string
	configure := &cobra.Command{
		Use:   "configure <existing-ssh-alias> --address IP:PORT --host-key-file FILE",
		Short: "Pin a trusted target host key and configure its overlay address",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireExperimental(); err != nil {
				return err
			}
			if address == "" || keyFile == "" {
				return fmt.Errorf("--address and --host-key-file are required")
			}
			stateDir, err := resolveDir()
			if err != nil {
				return err
			}
			keys, err := deps.readKeys(keyFile)
			if err != nil {
				return fmt.Errorf("read trusted host key: %w", err)
			}
			userConfig, brevConfig, executable, err := deps.paths(stateDir)
			if err != nil {
				return err
			}
			target := sshtransport.Target{ID: args[0], Alias: args[0], Address: address, HostKeyAlias: args[0], HostKeys: keys}
			if err := deps.configure(stateDir, userConfig, brevConfig, executable, target); err != nil {
				return err
			}
			cmd.Printf("Configured %s with a pinned SSH host key. Select direct transport with: brev tunnel use direct\n", args[0])
			return nil
		},
	}
	configure.Flags().StringVar(&address, "address", "", "target overlay IP and actual SSH server port")
	configure.Flags().StringVar(&keyFile, "host-key-file", "", "host public key obtained through a trusted channel")
	cmd.AddCommand(configure)

	cmd.AddCommand(&cobra.Command{
		Use: "use direct|gateway", Short: "Choose the transport for configured SSH aliases", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] != "direct" && args[0] != "gateway" {
				return fmt.Errorf("transport must be direct or gateway")
			}
			if args[0] == "direct" {
				if err := requireExperimental(); err != nil {
					return err
				}
			}
			stateDir, err := resolveDir()
			if err != nil {
				return err
			}
			if args[0] == "direct" {
				status, err := deps.status(cmd.Context(), stateDir)
				if err != nil {
					return err
				}
				if !status.Enrolled {
					return fmt.Errorf("this client is not enrolled; run 'brev tunnel enroll' before selecting direct transport")
				}
			}
			if err := deps.use(stateDir, args[0]); err != nil {
				return err
			}
			cmd.Printf("SSH transport: %s. This applies to new connections.\n", args[0])
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "status", Short: "Show local identity and helper status", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, err := resolveDir()
			if err != nil {
				return err
			}
			status, err := deps.status(cmd.Context(), stateDir)
			if err != nil {
				return err
			}
			mode, err := deps.mode(stateDir)
			if errors.Is(err, os.ErrNotExist) {
				mode, err = "gateway", nil
			}
			if err != nil {
				return err
			}
			cmd.Printf("Enrolled: %t\nHelper running: %t\nSSH transport: %s\n", status.Enrolled, status.Running, mode)
			if status.Enrolled {
				cmd.Printf("Device: %s\nManagement: %s\n", status.DeviceName, status.ManagementURL)
			}
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "stop", Short: "Stop the local helper; the next direct connection restarts it", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, err := resolveDir()
			if err != nil {
				return err
			}
			if err := deps.stop(cmd.Context(), stateDir); err != nil {
				return err
			}
			cmd.Println("Local tunnel stopped. The next direct connection restarts it; use 'brev tunnel use gateway' to stay disconnected.")
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "forget", Short: "Forget this local client identity and select gateway transport", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, err := resolveDir()
			if err != nil {
				return err
			}
			status, _ := deps.status(cmd.Context(), stateDir)
			if err := cleanupLocal(cmd.Context(), stateDir, deps.use, deps.forget); err != nil {
				return err
			}
			cmd.Println("Local client identity removed. Gateway transport selected; trusted host keys preserved.")
			if status.DeviceName != "" {
				cmd.Printf("Remote revocation is not complete. Ask your administrator to delete device %q in NetBird management (%s).\n", status.DeviceName, status.ManagementURL)
			} else {
				cmd.Println("Remote revocation is not complete. Ask your administrator to delete this peer in NetBird management.")
			}
			return nil
		},
	})
	return cmd
}

// CleanupLocal is also used by logout. It does not remove registered compute,
// revoke a remote peer, or erase SSH host-key pins.
func CleanupLocal(ctx context.Context, dir string) error {
	return cleanupLocal(ctx, dir, sshtransport.Use, nbembed.Forget)
}

func cleanupLocal(ctx context.Context, dir string, use func(string, string) error, forget func(context.Context, string) error) error {
	modeErr := use(dir, "gateway")
	if errors.Is(modeErr, os.ErrNotExist) {
		modeErr = nil
	}
	return errors.Join(modeErr, forget(ctx, dir))
}
