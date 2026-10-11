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
	"slices"
	"strconv"
	"strings"
	"time"

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
)

// meshTarget is where a Brev machine's sshd listens inside the NetBird overlay,
// plus the ssh_config alias whose user and certificate hook still apply.
type meshTarget struct {
	name  string
	id    string
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

// runShellViaNetbird execs the system ssh against the usual alias with the
// overlay hop supplied as a ProxyCommand (brev nb-proxy), which starts the
// embedded tunnel for the session. The alias entry is left untouched, so the
// Match host block that mints the certificate, the user and agent forwarding
// keep working.
//
// A live ssh ControlMaster for a target resolved within the reuse window
// means a previous session's tunnel is still up: ssh multiplexes over it and
// never runs the ProxyCommand, so the Brev lookups and the identity unlock
// are skipped. Otherwise the target is resolved and the identity unlocked
// here, while the terminal is still ours (inside the ProxyCommand every
// failure is a bare 255), and the unlock credentials are handed to nb-proxy
// through a one-shot file so it does not repeat the Brev API call.
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

	if t, ok := nbtunnel.LiveTarget(dir, spellings(nameOrID), nbtunnel.MasterAlive); ok {
		target := fromTarget(t)
		_, _ = fmt.Fprintf(os.Stderr, "Reusing the live tunnel to %s (NetBird %s) from a previous session.\n", target.alias, target.hostPort())
		failed, err := runNetbirdSSH(sstore, dir, target)
		if !failed {
			return err
		}
		// The master went away between the check and the connect, or the
		// machine behind the remembered address changed: start over once.
		_, _ = fmt.Fprintln(os.Stderr, "The previous tunnel is gone; connecting again from scratch.")
		if err := nbtunnel.ForgetTarget(dir, t.Alias); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}
	return connectCold(sstore, home, dir, id, nameOrID)
}

// spellings lists what a remembered target may be known as from the name a
// user typed: as is, or sanitized the way machine aliases are.
func spellings(nameOrID string) []string {
	return []string{nameOrID, ssh.SanitizeNodeName(nameOrID)}
}

func connectCold(sstore ShellStore, home, dir string, id nbtunnel.Identity, nameOrID string) error {
	ctx := context.Background()
	started := time.Now()
	// The unlock needs only the identity, so its Brev API call runs beside
	// the target lookup instead of after it.
	unlockCh := make(chan unlockResult, 1)
	go func() {
		creds, err := tunnel.Credentials(ctx, sstore, id)
		unlockCh <- unlockResult{creds: creds, err: err, took: time.Since(started)}
	}()
	target, err := resolveMeshTarget(ctx, sstore, nameOrID)
	if err != nil {
		stopStaleMaster(dir, nameOrID)
		return err
	}
	lookup := time.Since(started)
	// A master still alive for this alias past the reuse window: Brev was just
	// asked again, ssh will multiplex over it, and no new engine or lock is
	// needed. Otherwise the identity must be free, which a master left by a
	// session to another machine may still hold.
	reuse := nbtunnel.MasterAlive(target.alias)
	if !reuse {
		if err := freeIdentity(ctx, dir, target.alias); err != nil {
			return err
		}
	}
	unlock := <-unlockCh
	if unlock.err != nil {
		return breverrors.NewValidationError(unlock.err.Error())
	}
	if err := nbtunnel.CheckUnlock(dir, unlock.creds); err != nil {
		return breverrors.NewValidationError(err.Error())
	}
	configStart := time.Now()
	if err := ensureAliasConfigured(sstore, files.GetBrevSSHConfigPath(home), target.alias); err != nil {
		return err
	}
	sshConfig := time.Since(configStart)
	if err := nbtunnel.RememberTarget(dir, toTarget(target)); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: %v (the next reconnect will look the target up again)\n", err)
	}
	if !reuse {
		stash, err := tunnel.StashCredentials(dir, unlock.creds)
		if err != nil {
			return breverrors.WrapAndTrace(err)
		}
		// nb-proxy removes the file on read; this covers an ssh that never ran it.
		defer tunnel.RemoveStash(stash)
		if err := os.Setenv(tunnel.EnvUnlock, stash); err != nil {
			return breverrors.WrapAndTrace(err)
		}
	}

	note := ""
	if reuse {
		note = " (reusing the live tunnel of a previous session)"
	}
	_, _ = fmt.Fprintf(os.Stderr, "Resolved SSH target: %s via NetBird %s%s\n", target.alias, target.hostPort(), note)
	if nbtunnel.TimingEnabled() {
		_, _ = fmt.Fprintf(os.Stderr, "timing: target lookup %s, identity unlock %s (concurrent), ssh config %s; %s before ssh\n",
			fmtDur(lookup), fmtDur(unlock.took), fmtDur(sshConfig), fmtDur(time.Since(started)))
	}
	_, err = runNetbirdSSH(sstore, dir, target)
	return err
}

// freeIdentity makes sure no earlier session's master still holds the
// identity lock before a new engine starts for alias: idle masters are
// stopped, one with an open session keeps the lock and is named.
func freeIdentity(ctx context.Context, dir, alias string) error {
	err := nbtunnel.CheckAvailable(dir)
	if err == nil {
		return nil
	}
	if !errors.Is(err, nbtunnel.ErrLocked) {
		return breverrors.NewValidationError(err.Error())
	}
	stopped, err := nbtunnel.ReleaseIdleMasters(ctx, dir)
	if err != nil {
		return breverrors.NewValidationError(err.Error())
	}
	if len(stopped) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Stopped the idle tunnel to %s to start one for %s.\n", strings.Join(stopped, ", "), alias)
	}
	return nil
}

// stopStaleMaster ends a lingering master for a target Brev no longer
// resolves for this user, so a revoked access does not outlive the lookup.
func stopStaleMaster(dir, nameOrID string) {
	targets, err := nbtunnel.ReadTargets(dir)
	if err != nil {
		return
	}
	for _, t := range targets {
		if slices.Contains(spellings(nameOrID), t.Name) || slices.Contains(spellings(nameOrID), t.Alias) || t.ID == nameOrID {
			if nbtunnel.MasterAlive(t.Alias) {
				_ = nbtunnel.MasterStop(t.Alias)
			}
		}
	}
}

type unlockResult struct {
	creds nbtunnel.Credentials
	err   error
	took  time.Duration
}

func fmtDur(d time.Duration) string {
	return d.Round(10 * time.Millisecond).String()
}

func toTarget(m meshTarget) nbtunnel.Target {
	return nbtunnel.Target{Name: m.name, ID: m.id, Alias: m.alias, Addr: m.addr, Port: m.port, Host: m.host, Workspace: m.workspace != nil}
}

func fromTarget(t nbtunnel.Target) meshTarget {
	m := meshTarget{name: t.Name, id: t.ID, alias: t.Alias, addr: t.Addr.Unmap(), port: t.Port, host: t.Host}
	if t.Workspace {
		// Enough of the instance for the analytics event after the session.
		m.workspace = &entity.Workspace{ID: t.ID, Name: t.Name}
	}
	return m
}

// runNetbirdSSH runs the session; failed reports an ssh that could not
// connect (exit 255), as opposed to a remote command's own exit status.
func runNetbirdSSH(sstore ShellStore, dir string, target meshTarget) (failed bool, err error) {
	opts := netbirdSSHOptions(brevExecutable(), target)
	if err := runSSHWithOptions(target.alias, target.host, false, opts...); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() != sshFailureExit {
			// The session ran; the remote shell's own exit status is not ours.
			return false, nil
		}
		return true, breverrors.NewValidationError(fmt.Sprintf(
			"connection to %s over NetBird failed; the messages above say why (tunnel log: %s)",
			target.name, filepath.Join(dir, "tunnel.log")))
	}
	if target.workspace != nil {
		trackShellAnalytics(sstore, target.workspace)
	}
	return false, nil
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
		id:        workspace.ID,
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
		id:    node.GetExternalNodeId(),
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
// of starting a second peer; the master stays up for ControlPersist after the
// last session, holding the identity lock, and a connection to another
// machine stops it (see nbtunnel.ReleaseIdleMasters). ConnectTimeout covers
// the tunnel start and peer wait inside the proxy. Host keys follow the
// posture of every brev-generated entry.
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
		"-o", "ControlPath=" + nbtunnel.ControlPath,
		"-o", "ControlPersist=" + nbtunnel.ControlPersist,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
	}
}
