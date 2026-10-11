package shell

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	nodev1 "buf.build/gen/go/brevdev/devplane/protocolbuffers/go/devplaneapi/v1"
	"connectrpc.com/connect"
	"github.com/alessio/shellescape"

	"github.com/brevdev/brev-cli/pkg/cmd/refresh"
	"github.com/brevdev/brev-cli/pkg/cmd/register"
	"github.com/brevdev/brev-cli/pkg/cmd/tunnel"
	"github.com/brevdev/brev-cli/pkg/cmd/util"
	"github.com/brevdev/brev-cli/pkg/config"
	"github.com/brevdev/brev-cli/pkg/entity"
	breverrors "github.com/brevdev/brev-cli/pkg/errors"
	"github.com/brevdev/brev-cli/pkg/files"
	"github.com/brevdev/brev-cli/pkg/nbtunnel"
	"github.com/brevdev/brev-cli/pkg/ssh"
)

const (
	defaultSSHPort = 22
	// sshFailureExit is the status OpenSSH itself exits with; anything else is
	// the remote command's status and not a connection problem.
	sshFailureExit = 255
	// netbirdControlPath keeps --netbird sessions on their own control socket so
	// they never attach to a gateway-path master for the same alias.
	netbirdControlPath = "~/.brev/nb-control-%C"
)

// meshTarget is where a Brev machine's sshd listens inside the NetBird overlay,
// plus the ssh_config alias whose user and certificate hook still apply.
type meshTarget struct {
	name  string
	alias string
	addr  netip.Addr
	port  uint16
	// host selects the plain ssh invocation brev uses for machines rather
	// than the container shell wrapper it uses for instances.
	host      bool
	workspace *entity.Workspace
}

func (m meshTarget) hostPort() string {
	return net.JoinHostPort(m.addr.String(), strconv.Itoa(int(m.port)))
}

// runShellViaNetbird resolves the machine's overlay address and execs the
// system ssh against the usual alias with the overlay hop supplied as a
// ProxyCommand (brev nb-proxy), which starts the embedded tunnel for the
// session. The alias entry is left untouched, so the Match host block that
// mints the certificate, the user and agent forwarding keep working. Tunnel
// preconditions are checked here first, because once ssh is running every
// failure inside the ProxyCommand looks the same from the outside.
func runShellViaNetbird(sstore ShellStore, nameOrID string, host bool) error {
	if host {
		return breverrors.NewValidationError("--host cannot be combined with --netbird yet")
	}
	if _, err := sstore.GetAccessToken(); err != nil {
		return breverrors.WrapAndTrace(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return breverrors.WrapAndTrace(err)
	}
	dir := nbtunnel.Dir(home)
	id, err := nbtunnel.ReadIdentity(dir)
	if err != nil {
		return breverrors.NewValidationError(err.Error())
	}

	ctx := context.Background()
	target, err := resolveMeshTarget(ctx, sstore, nameOrID)
	if err != nil {
		return err
	}
	// A live control master for this alias means ssh will multiplex over the
	// running tunnel and spawn no second proxy, so the identity lock is fine
	// and nb-proxy will not have to unlock the identity again.
	if !controlMasterAlive(target.alias) {
		if err := nbtunnel.CheckAvailable(dir); err != nil {
			return breverrors.NewValidationError(err.Error())
		}
		// Prove the Brev session unlocks the identity while the terminal is
		// still ours: inside the ProxyCommand the same failure is a bare 255.
		creds, err := tunnel.Credentials(ctx, sstore, id)
		if err != nil {
			return breverrors.NewValidationError(err.Error())
		}
		if err := nbtunnel.CheckUnlock(dir, creds); err != nil {
			return breverrors.NewValidationError(err.Error())
		}
	}
	if err := ensureAliasConfigured(sstore, files.GetBrevSSHConfigPath(home), target.alias); err != nil {
		return err
	}

	opts := netbirdSSHOptions(brevExecutable(), target)
	_, _ = fmt.Fprintf(os.Stderr, "Resolved SSH target: %s via NetBird %s\n", target.alias, target.hostPort())
	if err := runSSHWithOptions(target.alias, target.host, false, opts...); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() != sshFailureExit {
			// The session ran; the remote shell's own exit status is not ours.
			return nil
		}
		return breverrors.NewValidationError(fmt.Sprintf(
			"connection to %s over NetBird failed; the messages above say why (tunnel log: %s)",
			target.name, filepath.Join(dir, "tunnel.log")))
	}
	if target.workspace != nil {
		trackShellAnalytics(sstore, target.workspace)
	}
	return nil
}

// ensureAliasConfigured regenerates ~/.brev/ssh_config when the alias is not
// in it yet, so the first ssh attempt already carries the user and the
// certificate hook instead of failing into an interactive prompt.
func ensureAliasConfigured(sstore ShellStore, configPath, alias string) error {
	configured, err := aliasConfigured(configPath, alias)
	if err == nil && configured {
		return nil
	}
	_, _ = fmt.Fprintln(os.Stderr, "Refreshing SSH config...")
	if err := refresh.RunRefreshAsync(sstore).Await(); err != nil {
		return breverrors.WrapAndTrace(err)
	}
	return nil
}

// aliasConfigured reports whether configPath has a Host or Match host block
// for alias.
func aliasConfigured(configPath, alias string) (bool, error) {
	f, err := os.Open(configPath)
	if err != nil {
		return false, fmt.Errorf("open ssh config: %w", err)
	}
	defer f.Close() //nolint:errcheck // read only

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		switch {
		case len(fields) >= 2 && strings.EqualFold(fields[0], "Host") && fields[1] == alias:
			return true, nil
		case len(fields) >= 3 && strings.EqualFold(fields[0], "Match") && strings.EqualFold(fields[1], "host") && fields[2] == alias:
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("read ssh config: %w", err)
	}
	return false, nil
}

// controlMasterAlive asks OpenSSH whether a --netbird control master for alias
// is still running.
func controlMasterAlive(alias string) bool {
	cmd := exec.Command("ssh", "-o", "ControlPath="+netbirdControlPath, "-O", "check", alias) //nolint:gosec // alias is the resolved brev ssh alias
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Run() == nil
}

// brevExecutable returns the running binary for the ProxyCommand, matching
// how the mint-cert hook is generated.
func brevExecutable() string {
	bin, err := os.Executable()
	if err != nil {
		return "brev"
	}
	return bin
}

func resolveMeshTarget(ctx context.Context, sstore ShellStore, nameOrID string) (meshTarget, error) {
	resolved, err := util.ResolveWorkspaceOrNodeWithContext(ctx, sstore, nameOrID)
	if err != nil {
		return meshTarget{}, breverrors.WrapAndTrace(err)
	}
	user, err := sstore.GetCurrentUser()
	if err != nil {
		return meshTarget{}, breverrors.WrapAndTrace(err)
	}
	if resolved.Node != nil {
		return nodeMeshTarget(ctx, sstore, user, resolved.Node)
	}
	workspace := resolved.Workspace
	if err := util.RequireRunning(workspace); err != nil {
		return meshTarget{}, err //nolint:wrapcheck // do not present stack trace for this error
	}
	return workspaceMeshTarget(ctx, sstore, user, workspace)
}

// workspaceMeshTarget asks Brev for the instance's overlay address and the port
// its sshd listens on behind the caller's SSH access.
func workspaceMeshTarget(ctx context.Context, sstore ShellStore, user *entity.User, workspace *entity.Workspace) (meshTarget, error) {
	client := register.NewEnvironmentServiceClient(sstore, config.GlobalConfig.GetBrevPublicAPIURL())
	envRes, err := client.GetEnvironment(ctx, connect.NewRequest(&nodev1.GetEnvironmentRequest{
		EnvironmentId: workspace.ID,
		AttachedDataOptions: &nodev1.GetEnvironmentAttachedDataOptions{
			SshAccess: true,
		},
	}))
	if err != nil {
		return meshTarget{}, fmt.Errorf("get environment: %w", err)
	}
	portID := ""
	for _, access := range envRes.Msg.GetEnvironment().GetSshAccess() {
		if access.GetUserId() == user.ID && access.GetPortId() != "" {
			portID = access.GetPortId()
			break
		}
	}

	netRes, err := client.GetNetworkInfo(ctx, connect.NewRequest(&nodev1.EnvironmentServiceGetNetworkInfoRequest{
		EnvironmentId: workspace.ID,
	}))
	if err != nil {
		return meshTarget{}, fmt.Errorf("get network info: %w", err)
	}
	info := netRes.Msg.GetNetworkInfo()
	addr, err := parseMeshAddr(info.GetMeshIpAddress(), workspace.Name)
	if err != nil {
		return meshTarget{}, err
	}
	return meshTarget{
		name:      workspace.Name,
		alias:     string(workspace.GetLocalIdentifier()),
		addr:      addr,
		port:      sshServerPort(info.GetPorts(), portID),
		workspace: workspace,
	}, nil
}

// nodeMeshTarget resolves a Brev Connect machine the same way, from the node's
// connectivity info and the caller's SSH access entry.
func nodeMeshTarget(ctx context.Context, sstore ShellStore, user *entity.User, node *nodev1.ExternalNode) (meshTarget, error) {
	entry := util.ResolveNodeSSHEntry(user.ID, node)
	if entry == nil {
		if _, err := util.ResolveExternalNodeSSH(sstore, node); err != nil {
			return meshTarget{}, err //nolint:wrapcheck // actionable validation error
		}
		return meshTarget{}, breverrors.NewValidationError(fmt.Sprintf("no SSH access found for %s", node.GetName()))
	}

	client := register.NewNodeServiceClient(sstore, config.GlobalConfig.GetBrevPublicAPIURL())
	res, err := client.GetNode(ctx, connect.NewRequest(&nodev1.GetNodeRequest{
		ExternalNodeId: node.GetExternalNodeId(),
	}))
	if err != nil {
		return meshTarget{}, fmt.Errorf("get node: %w", err)
	}
	full := res.Msg.GetExternalNode()
	addr, err := parseMeshAddr(full.GetConnectivityInfo().GetMeshIpAddress(), node.GetName())
	if err != nil {
		return meshTarget{}, err
	}
	return meshTarget{
		name:  node.GetName(),
		alias: ssh.SanitizeNodeName(node.GetName()),
		addr:  addr,
		port:  sshServerPort(full.GetPorts(), entry.PortID),
		host:  true,
	}, nil
}

func parseMeshAddr(raw, name string) (netip.Addr, error) {
	if raw == "" {
		return netip.Addr{}, breverrors.NewValidationError(fmt.Sprintf(
			"%s has no NetBird address; make sure it is in the mesh (Network mode in the Brev dashboard) and try again", name))
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return prefix.Addr().Unmap(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse NetBird address %q of %s: %w", raw, name, err)
	}
	return addr.Unmap(), nil
}

// sshServerPort returns the port sshd listens on behind the user's SSH access
// port, falling back to 22 when Brev did not report one.
func sshServerPort(ports []*nodev1.Port, portID string) uint16 {
	for _, p := range ports {
		if p.GetPortId() == portID && p.GetServerPort() > 0 && p.GetServerPort() <= 65535 {
			return uint16(p.GetServerPort())
		}
	}
	return defaultSSHPort
}

// netbirdSSHOptions supplies the overlay hop as the ProxyCommand and disables
// anything in the alias entry that would route around it. HostName is left
// alone on purpose: OpenSSH evaluates `Match host` against the substituted
// hostname, so overriding it would skip the block that mints the certificate.
// Sessions multiplex over a brev-owned control socket, so a second
// `brev ssh --netbird` to the same machine reuses the running tunnel instead
// of starting a second peer; the master lingers briefly after the last
// session so the tunnel and its lock go away soon afterwards. ConnectTimeout
// covers the tunnel start and peer wait inside the proxy. Host keys follow
// the posture of every brev-generated entry.
func netbirdSSHOptions(brevBin string, target meshTarget) []string {
	// OpenSSH percent-expands ProxyCommand, so a literal % in the path must
	// be doubled.
	bin := strings.ReplaceAll(brevBin, "%", "%%")
	proxy := shellescape.QuoteCommand([]string{bin, "nb-proxy", target.addr.String(), strconv.Itoa(int(target.port))})
	return []string{
		"-o", "ProxyCommand=" + proxy,
		"-o", "ProxyJump=none",
		"-o", "ConnectTimeout=90",
		"-o", "ControlMaster=auto",
		"-o", "ControlPath=" + netbirdControlPath,
		"-o", "ControlPersist=30s",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
	}
}
