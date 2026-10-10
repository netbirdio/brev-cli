package shell

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	nodev1 "buf.build/gen/go/brevdev/devplane/protocolbuffers/go/devplaneapi/v1"
	"connectrpc.com/connect"

	"github.com/brevdev/brev-cli/pkg/cmd/refresh"
	"github.com/brevdev/brev-cli/pkg/cmd/register"
	"github.com/brevdev/brev-cli/pkg/cmd/util"
	"github.com/brevdev/brev-cli/pkg/config"
	"github.com/brevdev/brev-cli/pkg/entity"
	breverrors "github.com/brevdev/brev-cli/pkg/errors"
	"github.com/brevdev/brev-cli/pkg/nbtunnel"
	"github.com/brevdev/brev-cli/pkg/ssh"
	"github.com/brevdev/brev-cli/pkg/terminal"
)

const (
	defaultSSHPort  = 22
	tunnelStartWait = 60 * time.Second
	peerConnectWait = 25 * time.Second
)

// meshTarget is where a Brev machine's sshd listens inside the NetBird overlay,
// plus the ssh_config alias whose user and certificate hook still apply.
type meshTarget struct {
	name      string
	alias     string
	addr      netip.Addr
	port      uint16
	workspace *entity.Workspace
}

func (m meshTarget) hostPort() string {
	return net.JoinHostPort(m.addr.String(), strconv.Itoa(int(m.port)))
}

// runShellViaNetbird opens the embedded tunnel, waits for the target peer, and
// execs the system ssh against the usual alias with HostName and Port pointed
// at a loopback relay into the overlay. Everything else in the alias entry,
// the user, the mint-cert hook, agent forwarding, keeps working unchanged.
func runShellViaNetbird(t *terminal.Terminal, sstore ShellStore, nameOrID string, host bool) error {
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
	tunnel, err := nbtunnel.Open(nbtunnel.Dir(home))
	if err != nil {
		if errors.Is(err, nbtunnel.ErrNotRegistered) || errors.Is(err, nbtunnel.ErrLocked) {
			return breverrors.NewValidationError(err.Error())
		}
		return breverrors.WrapAndTrace(err)
	}
	defer tunnel.Close()

	ctx := context.Background()
	target, err := resolveMeshTarget(ctx, sstore, nameOrID)
	if err != nil {
		return err
	}
	if err := connectTunnel(ctx, t, tunnel, target); err != nil {
		return err
	}
	local, err := tunnel.ListenLoopback(target.hostPort())
	if err != nil {
		return breverrors.WrapAndTrace(err)
	}
	_, _ = fmt.Fprintf(os.Stderr, "Resolved SSH target: %s via NetBird %s\n", target.alias, target.hostPort())

	opts := netbirdSSHOptions(local)
	if err := runSSHWithOptions(target.alias, false, false, opts...); err == nil {
		trackNetbirdShell(sstore, target)
		return nil
	}
	// The alias may be missing from ~/.brev/ssh_config on a fresh install.
	// brev shell handles that the same way: refresh the config and retry once.
	_, _ = fmt.Fprintln(os.Stderr, "\nConnection failed, refreshing SSH config and retrying...")
	if err := refresh.RunRefreshAsync(sstore).Await(); err != nil {
		return breverrors.WrapAndTrace(err)
	}
	if err := runSSHWithOptions(target.alias, false, true, opts...); err != nil {
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

func connectTunnel(ctx context.Context, t *terminal.Terminal, tunnel *nbtunnel.Tunnel, target meshTarget) error {
	s := t.NewSpinner()
	s.Suffix = " connecting to the Brev tunnel"
	s.Start()
	startCtx, cancel := context.WithTimeout(ctx, tunnelStartWait)
	err := tunnel.Start(startCtx)
	cancel()
	s.Stop()
	if err != nil {
		return breverrors.NewValidationError(fmt.Sprintf(
			"could not start the embedded Brev tunnel: %v\n"+
				"If this device was removed from Brev, run 'brev deregister' and 'brev register --embedded' again.", err))
	}

	s.Suffix = fmt.Sprintf(" waiting for %s to be reachable over NetBird", target.name)
	s.Start()
	waitCtx, cancel := context.WithTimeout(ctx, peerConnectWait)
	err = tunnel.WaitForPeer(waitCtx, target.addr)
	cancel()
	s.Stop()
	if err != nil {
		return breverrors.NewValidationError(fmt.Sprintf("%s is not reachable over NetBird: %v", target.name, err))
	}
	return nil
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

// netbirdSSHOptions points OpenSSH at the loopback relay while the alias entry
// keeps supplying the user, the certificate hook and the rest. ControlMaster is
// off because the relay lives only as long as this brev process.
func netbirdSSHOptions(localAddr string) []string {
	host, port, err := net.SplitHostPort(localAddr)
	if err != nil {
		host, port = "127.0.0.1", localAddr
	}
	return []string{
		"-o", "HostName=" + host,
		"-o", "Port=" + port,
		"-o", "ConnectTimeout=15",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
	}
}
