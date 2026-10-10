package shell

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"

	nodev1 "buf.build/gen/go/brevdev/devplane/protocolbuffers/go/devplaneapi/v1"
	"connectrpc.com/connect"
	"github.com/alessio/shellescape"

	"github.com/brevdev/brev-cli/pkg/cmd/refresh"
	"github.com/brevdev/brev-cli/pkg/cmd/register"
	"github.com/brevdev/brev-cli/pkg/cmd/util"
	"github.com/brevdev/brev-cli/pkg/config"
	"github.com/brevdev/brev-cli/pkg/entity"
	breverrors "github.com/brevdev/brev-cli/pkg/errors"
	"github.com/brevdev/brev-cli/pkg/nbtunnel"
	"github.com/brevdev/brev-cli/pkg/ssh"
)

const defaultSSHPort = 22

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
// mints the certificate, the user and agent forwarding keep working.
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
	if !nbtunnel.IsRegistered(nbtunnel.Dir(home)) {
		return breverrors.NewValidationError(nbtunnel.ErrNotRegistered.Error())
	}

	target, err := resolveMeshTarget(context.Background(), sstore, nameOrID)
	if err != nil {
		return err
	}
	opts := netbirdSSHOptions(brevExecutable(), target)
	_, _ = fmt.Fprintf(os.Stderr, "Resolved SSH target: %s via NetBird %s\n", target.alias, target.hostPort())

	if err := runSSHWithOptions(target.alias, target.host, false, opts...); err == nil {
		trackNetbirdShell(sstore, target)
		return nil
	}
	// The alias may be missing from ~/.brev/ssh_config on a fresh install.
	// brev shell handles that the same way: refresh the config and retry once.
	_, _ = fmt.Fprintln(os.Stderr, "\nConnection failed, refreshing SSH config and retrying...")
	if err := refresh.RunRefreshAsync(sstore).Await(); err != nil {
		return breverrors.WrapAndTrace(err)
	}
	if err := runSSHWithOptions(target.alias, target.host, true, opts...); err != nil {
		return breverrors.WrapAndTrace(err)
	}
	trackNetbirdShell(sstore, target)
	return nil
}

func trackNetbirdShell(sstore ShellStore, target meshTarget) {
	if target.workspace != nil {
		trackShellAnalytics(sstore, target.workspace)
	}
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
// ControlMaster is off because the proxy lives only as long as this session,
// and ConnectTimeout covers the tunnel start and peer wait inside it.
func netbirdSSHOptions(brevBin string, target meshTarget) []string {
	proxy := shellescape.QuoteCommand([]string{brevBin, "nb-proxy", target.addr.String(), strconv.Itoa(int(target.port))})
	return []string{
		"-o", "ProxyCommand=" + proxy,
		"-o", "ProxyJump=none",
		"-o", "ConnectTimeout=90",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
	}
}
