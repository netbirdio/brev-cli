# SSH into Brev machines over NetBird: UX options

Scope: `netbirdio/netbird` at 01d828d and `brevdev/brev-cli` at d4217d9 (two commits above the 2f82fb3 in the brief, adding the `nbproxy`/`nbembed` prototype, Go 1.26 and the netbird require). Prior input: `brev-netbird-embed-ssh-feasibility.md`. Brev infrastructure facts (shared NetBird account on 100.73.0.0/16, gateway peers, Global Accelerator, nport mapping, VM map contents) are not visible in either checkout and are marked *inferred*.

Corrections to the brief: API keys use the `bak-` prefix (`pkg/auth/auth.go:106`); `brev exec` resolves workspaces only (`pkg/cmd/exec/exec.go:199`); `NetworkMemberType` has only `ISOLATED` and `SHARED` (`network.pb.go:73-75`); `nport` is a Port ID prefix (`pkg/cmd/ports/get.go:29-30`) and the fixture SSH hostname is `global.prd.ga.run.brev.nvidia.com:<port>` (`pkg/cmd/ports/ports_test.go:155`); node entries carry a plain `Host` fallback block after the cert `Match` block (`pkg/ssh/sshconfigurer.go:111-131`), environment entries do not (`:462-531`).

## 1. Recommendation

Ship Option B: brev-cli links `client/embed` and runs one unprivileged netstack peer per user inside an on-demand helper (`brev nb-agent`) that an OpenSSH ProxyCommand (`brev nb-proxy`) spawns, so `brev shell`, `exec`, `port-forward`, `open`, `copy`, the 5-minute certificate hook, ControlMaster and ForwardAgent run exactly as today with only the ssh_config block changed, nothing installed, no sudo, one binary for macOS, Linux and WSL2. Graft from D the per-target map check before exec, the `brev tunnel status` doctor view, an explicit `--transport` that never falls back silently, enrollment offered at `brev login`, the `{transport, fallback_reason}` analytics gate per rollout stage and ControlMaster on node entries; graft from C the no-grant message and the `brev ls` columns; and pull host-key pinning and the console revoke into the first post-MVP release. Do not make A the default (root daemon with host routing changes, no WSL2, org-visible ExternalNode, profile exclusivity with a corporate NetBird) and do not pursue C (JWT-only NetBird SSH server: no agent forwarding, a 10-minute token window that makes management a per-session dependency, every Brev user becoming a NetBird user in one shared account, an unconditional 22 to 22022 DNAT that captures the gateway path).

Judges' ranking: B 30, D 26, A 20, C 14 (D won the persona lens, B the other three).

## 2. Comparison

| Row | A: native daemon, direct dial | B: embedded helper + ProxyCommand | C: NetBird SSH server + Dex exchange | D: hybrid auto-detect, staged |
|---|---|---|---|---|
| First-run steps | `brev login`; `brev register --client-only` (sudo once); unprivileged `netbird up --profile brev`; `brev refresh` | `brev login`; one y/N on first use; refresh inline | `brev login` enrolls inline (token exchange, JWT peer login) | `brev login` offers embedded enrollment; daemon mode optional |
| Time to first shell | 2-4 min (download, sudo, `netbird up`, first ssh) | About 4 s machine time after login | 20-30 s wall clock incl. browser | 10-15 s embedded; +30-90 s and sudo for daemon |
| Root needed | Once at install; root daemon for life; `up/status/down` unprivileged over the 0666 socket (`client/cmd/service_socket.go:115`) | Never | Laptop never; VM root once for SSH-server flags and sshd port 2222 | Embedded never; daemon once |
| Platforms | Linux, macOS; no WSL2, no Windows | macOS, Linux, WSL2; no native Windows (brev ships none) | Laptops as B; native variant opens a browser per session | Embedded as B; daemon Linux/macOS |
| IDE and tooling | VS Code, scp, rsync, ForwardAgent unchanged; JetBrains fixable | Same via ProxyCommand; JetBrains on GA | VS Code via stdio proxy; no agent forwarding; SFTP and forwarding host-wide; JetBrains, mosh, X11 lost | As B |
| Per-session latency | ~2 s cold master, 50-200 ms multiplexed; +5 s detect probe unless `99-netbird.conf` disabled | Warm within tens of ms of GA; 1.5-3 s cold after 30 min idle | Token exchange per new master plus peer path | As B; 30 s stall on peer-unreachable |
| Auth and revocation | sshd + 5-min cert; WG key root-owned; setup-key peer never expires (`management/server/peer.go:804-808`); Brev deletes peer | Same boundary; key in 0700 `~/.brev/netbird`; one-off key consumed in-process; RevokeDevice deletes peer | Dex token as SSH password, iat under 600 s (`client/ssh/server/server.go:51-54,575-606`); user-owned peer expires 24 h; token is also an API bearer | As B; one live peer per device |
| Tenancy and policy | Per-org groups, tcp/22 rule; laptop is an org ExternalNode until backend enforcement (*inferred*) | Per-org `brev-devices-<org>`, one unidirectional tcp/22 rule; no ExternalNode, no NetBird users | Single-account mode, NetBird user per Brev user, `netbird-ssh` policy per VM or org | As B; node attach merges exposures |
| Host keys | Unchecked as today; stable mesh IP enables pinning | Unchecked; transport bound to a management-vouched identity; pin in phase 3 | Strict for free (`shared/management/networkmap/encode.go:286`) | As B; stage 4 pins NB blocks only |
| Brev backend | AddNode client kind, `ConnectivityInfo.setup_key/management_url`, RPC refusals on client nodes, peer delete on RemoveNode | DeviceService (Enroll, Confirm, Revoke, List), one-off keys, device table, console revoke | EmbeddedIdP + NVIDIA connector, single-account mode, policy reconciler, VM flags, sshd 2222 | B plus GetDeviceEnrollment, `policy_state`, node attach |
| brev-cli | 500-800 LOC, no go.mod change | 700-1000 LOC, Go 1.26, three replaces, +25-36 MB | B plus token exchange and a stdio proxy clone | 1200-1600 LOC, B plus resolver |
| NetBird upstream | None required | None required; five optional embed PRs | None required; pluggable proxy, agent forwarding, DNAT opt-out wanted | None required; same five PRs |
| Ops | Groups, policy, topology choice, service env | Topology spike, groups, policy, public endpoints, relay capacity, flag | Dex storage, NVIDIA client, JWKS from Isolated VMs, fleet port move | As B plus stage gates |
| Biggest risk | Root daemon rewrites routing and resolver; 100.73/16 route collides with Tailscale's CGNAT range (*inferred*); profile exclusivity | Topology unverified; binary and toolchain cost | One bad policy write is a cross-org shell; DNAT breaks GA teammates per VM | Three transports; silent fallback masks breakage |

## 3. Options

Transcript hostnames and IDs are placeholders; timings are code-derived unless stated as measured.

### Option A: Brev Connect as laptop enrollment, native daemon, OpenSSH dials the overlay IP

`brev register --client-only` installs the stock package with sudo once, then runs `netbird up --profile brev -n brev-<user>-<host> -m <url> --setup-key <key> --block-inbound --disable-server-routes --disable-client-routes --disable-dns` as the user (a fresh profile stores `ServerSSHAllowed=false`, `profilemanager/config.go:308-318`, and the gate covers only SSH-server, remote-jobs, metrics and URL changes while SSH is on, `client/server/ssh_gate.go:85-126`). `brev refresh` writes `Hostname <mesh IP>`, `Port 22`, no ProxyCommand. `netbird ssh` is never offered: it returns the VM's NetBird-generated key and has no certificate auth (`client/ssh/client/client.go:303-311,450-480`).

First run:

```
Fresh macOS laptop (Apple silicon), never ran NetBird, brev 0.6.x with client-only support. Timings in brackets are estimates derived from code paths and the prior report's measurements, not measured in this container. The management URL is a placeholder; the real one arrives in ConnectivityInfo.management_url.

alice@mbp ~ % brev login
Open this link in your browser to log in:
  https://brev.nvidia.com/cli-login?sessionKey=...
Waiting for login...                                                   [browser SSO, 0:00-0:22]
Logged in as alice@acme.com (org: acme)

alice@mbp ~ % brev register --client-only
  Device registration requires elevated (sudo) privileges.
  You will be prompted for your password by sudo.

? Device registration requires sudo. Continue?  Yes, proceed
Password:                                                              [0:30]

══════════════════════════════════════════════════
  Registering this laptop as a Brev client device
══════════════════════════════════════════════════

  Device:        mbp-alice
  Organization:  acme (org_2k9f...)

  This will:
    1. Install the Brev tunnel (NetBird) once, using sudo
    2. Register this laptop as a client device (no hardware profile, no SSH target)
    3. Connect the tunnel as NetBird profile "brev", without sudo
    4. Store a device record under ~/.brev

? Proceed with registration?  Yes, proceed

[Step 1/4] Installing Brev tunnel...
  Downloading netbird 0.81.0 (darwin/arm64)...
  netbird service install
  netbird service start
  netbird service reconfigure --service-env NB_DISABLE_SSH_CONFIG=true
  ✓  Brev tunnel ready (daemon running, no NetBird menu bar app installed)   [0:35-1:25]

[Step 2/4] Registering client device with Brev...
  ✓  Registered as client device extnode_7b1c... (hidden from 'brev ls nodes')   [1:27]

[Step 3/4] Connecting Brev tunnel (profile "brev")...
  netbird up --profile brev -n brev-alice-mbp -m https://mgmt.brev.example:443 \
    --setup-key **** --block-inbound --disable-server-routes --disable-client-routes --disable-dns
  Connected                                                            [1:31]
  Management: Connected to https://mgmt.brev.example:443
  Overlay address: 100.73.21.7
  ✓  Device connected

[Step 4/4] Saving device record...
  ✓  Wrote /Users/alice/.brev/device.json (0600)

  ✓  Registration complete.
  Instances in acme are now reachable over the Brev tunnel. Run: brev refresh

alice@mbp ~ % brev refresh                                              [1:35-1:38]
brev has been refreshed

alice@mbp ~ % grep -B1 -A6 '^Host my-gpu-box$' ~/.brev/ssh_config
Match host my-gpu-box exec "/opt/homebrew/bin/brev mint-cert --env env_01hx... --port port_9a2... --linux-user ubuntu --out-key /Users/alice/.brev/ssh-certs/env_01hx..."
  Hostname 100.73.5.12
  IdentityFile "/Users/alice/.brev/ssh-certs/env_01hx..."
  User ubuntu
  ConnectTimeout 15
  ...
  ControlMaster auto
  ControlPath ~/.ssh/brev-control-%C
  ControlPersist 10m
  Port 22

alice@mbp ~ % brev shell my-gpu-box
Resolved SSH target: ubuntu@100.73.5.12:22
Warning: Permanently added '100.73.5.12' (ED25519) to the list of known hosts.
ubuntu@my-gpu-box:~$                                                   [1:40-1:43; cold: mint-cert RPC 0.4 s, peer idle->connected 1.5 s, handshake 0.5 s]
ubuntu@my-gpu-box:~$ exit

alice@mbp ~ % netbird status
OS: darwin/arm64
Daemon version: 0.81.0
CLI version: 0.81.0
Profile: brev
Management: Connected
Signal: Connected
Relays: 1/1 Available
Nameservers: 0/0 Available
FQDN: brev-alice-mbp.<brev-dns-domain>
NetBird IP: 100.73.21.7/16
Interface type: Userspace
Wireguard port: 51820
Quantum resistance: false
Lazy connection: false
SSH Server: Disabled
Networks: -
Peers count: 1/3 Connected
(abridged; field order from client/status/status.go:596-615)

Linux differences: install.sh adds the apt or yum repo and installs the netbird package (install.sh:114-136,235-268); the interface is wt0; 'netbird status' shows Interface type: Kernel. Everything else is identical. Total wall-clock to first prompt: about 1:45 here, 2-4 minutes on slow networks, dominated by the download and the sudo prompt.
```

Daily:

```
Next morning. The laptop woke from sleep; the daemon auto-connected at boot (client/cmd/root.go:221) and re-logged in with the stored key, so nothing to start. Timings estimated from code paths.

alice@mbp ~ % brev ls
NAME          STATUS     ...
my-gpu-box    RUNNING    ...
trainer-2     RUNNING    ...

alice@mbp ~ % brev shell my-gpu-box
Resolved SSH target: ubuntu@100.73.5.12:22
ubuntu@my-gpu-box:~$ nvidia-smi -L
GPU 0: NVIDIA H100 80GB HBM3 (UUID: GPU-...)
ubuntu@my-gpu-box:~$ git pull
Already up to date.                                   (ForwardAgent yes still works: sshd, not the NetBird SSH server)
ubuntu@my-gpu-box:~$ exit
                                                      [prompt in ~2.0 s: new ControlMaster, mint-cert cache hit 30 ms, peer idle->connected ~1.4 s]

alice@mbp ~ % brev exec my-gpu-box "nvidia-smi --query-gpu=utilization.gpu --format=csv"
utilization.gpu [%]
97 %                                                  [0.3 s: multiplexed over the master, no authentication, no mint RPC]

alice@mbp ~ % brev port-forward my-gpu-box -p 8888:8888
Port forwarding...
localhost:8888 -> my-gpu-box:8888                     [0.2 s; ssh -T -L 8888:127.0.0.1:8888 my-gpu-box -N over the same master]
^C

alice@mbp ~ % brev open my-gpu-box
Opening VS Code...                                    [VS Code Remote-SSH: vscode-remote://ssh-remote+my-gpu-box/home/ubuntu/project, window in ~4 s; the Remote-SSH extension reads ~/.ssh/config, which includes ~/.brev/ssh_config]

alice@mbp ~ % brev copy ./data.tar my-gpu-box:/home/ubuntu/
✓ Successfully copied ./data.tar → my-gpu-box:/home/ubuntu/ (1.9s)
                                                      [rsync over ssh; P2P WireGuard between the laptop and the VM, no accelerator hop]

alice@mbp ~ % netbird status -d --filter-by-names my-gpu-box
 my-gpu-box.<brev-dns-domain>:
  NetBird IP: 100.73.5.12
  Public key: ...
  Status: Connected
  -- detail --
  Connection type: P2P
  ICE candidate (Local/Remote): host/srflx
  Last connection update: 2 minutes ago
  Last WireGuard handshake: 48 seconds ago
  Transfer status (received/sent) 512.0 MiB/9.1 MiB
  Latency: 11ms
(abridged)

Ten minutes after the last command the ControlMaster exits (ControlPersist 10m); the next brev command pays the ~2 s cold path again. Nothing in this day asked for sudo, a browser, or a NetBird-specific command.
```

Failures:

```
Five failures the Brev user can hit on this option. Error texts marked (existing) are current brev-cli or netbird strings; the rest are the proposed classified lines.

1. VM stopped
alice@mbp ~ % brev shell my-gpu-box
instance my-gpu-box is not running, please start it with: brev start my-gpu-box        (existing, util/ssh.go:28-36)

2. VM running but not shared with the laptop (no clients-to-vms policy for this org, or the VM is outside the brev-vms group)
alice@mbp ~ % brev refresh
brev: my-gpu-box is not reachable over the Brev tunnel (peer not in this device's network map); using the public endpoint
brev has been refreshed
alice@mbp ~ % brev shell my-gpu-box
Resolved SSH target: ubuntu@a1b2c3.awsglobalaccelerator.com:40212               (GA entry; works as today)
Without the refresh-time check the user would instead see, after 15 s:
ssh: connect to host 100.73.5.12 port 22: Operation timed out
Connection failed, refreshing SSH config and retrying...                        (existing, shell.go:170)

3. Device revoked by Brev (RemoveNode from the console, idle sweep, or an admin DELETE /api/peers/{id})
The daemon received an empty map and a closed sync channel (management/internals/controllers/network_map/controller/controller.go:1334-1351), reconnected, got PermissionDenied and set NeedsLogin (client/internal/connect.go:357-358,526-528).
alice@mbp ~ % netbird status
Daemon status: NeedsLogin

Run UP command to log in with SSO (interactive login):

 netbird up
...                                                                              (existing, client/cmd/status.go:84-96; the SSO hint is wrong for Brev)
alice@mbp ~ % brev shell my-gpu-box
brev: Brev tunnel needs re-enrollment (device revoked or expired); run: brev register --client-only
brev: using the public endpoint for my-gpu-box
Resolved SSH target: ubuntu@a1b2c3.awsglobalaccelerator.com:40212
Re-enrollment issues a new one-off key and a new peer with a new mesh IP; the old key cannot be replayed (usage_limit 1).

4. Daemon not running (service stopped, or install.sh failed its 'service install' step on a WSL2 box without systemd)
alice@mbp ~ % netbird status
failed to connect to daemon error: context deadline exceeded
If the daemon is not running please run:
netbird service install
netbird service start                                                            (existing, client/cmd/status.go:166-170)
alice@mbp ~ % brev shell my-gpu-box
brev: Brev tunnel daemon is not running; start it with: sudo netbird service start
brev: using the public endpoint for my-gpu-box
Today's 'brev register' would have printed 'Registration complete' in this state (register.go:373-378); --client-only fails Step 3 instead.

5. Daemon on another NetBird account (the user selected their company profile from the tray or with 'netbird profile select corp')
alice@mbp ~ % brev refresh
brev: Brev tunnel is on NetBird profile "corp" (management https://corp.example); run 'netbird profile select brev' to use the direct path (this disconnects "corp"); using the public endpoint
alice@mbp ~ % brev register --client-only
brev: this laptop's netbird daemon is connected to https://corp.example (profile "corp"); connecting to Brev will disconnect it. Re-run with --switch-profile to proceed, or use the embedded tunnel (brev tunnel enroll) to keep both.
Today's 'brev register' would have hit 'Already connected' inside 'netbird up' (client/cmd/up.go:341-346) and still printed 'Registration complete'.

6. Management unreachable (captive portal, Brev management outage)
alice@mbp ~ % brev shell my-gpu-box
brev: Brev tunnel management is unreachable (Disconnected, reason: dial tcp ...: i/o timeout); peers may still connect over cached config; trying the tunnel first, public endpoint if it fails
Resolved SSH target: ubuntu@100.73.5.12:22
ubuntu@my-gpu-box:~$                                                             (an established WireGuard path survives a management outage; a cold peer does not)
```

Required changes. Backend: AddNode accepts nil `node_spec` and label `brev.nvidia.com/kind=client`, mints a one-off key (`openapi.yml:1264-1299`) into `brev-clients-<org>` and returns it in new `ConnectivityInfo.setup_key` and `management_url` fields; client nodes excluded from ListNodes and refused by OpenPort, GrantNodeSSHAccess, SetNetworkMemberType and IssueExternalNodeSSHCertificate; RemoveNode deletes the peer (`openapi.yml:7409`); mesh fields populated; per-org policy; sweep. brev-cli: `--client-only` and `--switch-profile` with the `LinuxPlatform` gate lifted for this path (`register/providers.go:88-91`); install with `USE_BIN_INSTALL=true SKIP_UI_APP=true` plus `netbird service reconfigure --service-env NB_DISABLE_SSH_CONFIG=true`; an `nbstatus` package over `netbird status --json`; success only after the Brev management URL is confirmed (fixes `register.go:373-378` and the `Already connected` short-circuit, `client/cmd/up.go:341-346`); `~/.brev/device.json` 0600; NB templates with `ConnectTimeout 15` and raised timeouts in `shell.go:187-190`, `exec.go:189,266`, `open.go:631`; client-label filtering in ls, grant-ssh, ports; `deregister --client-only` without `UninstallNetbird` (`register/netbird.go:43-71`). NetBird: none required; nice to have a per-profile opt-out for `99-netbird.conf` (`client/ssh/config/manager.go:21-35`) and a suppressed SSO hint for setup-key profiles (`client/cmd/status.go:84-96`). Ops: groups and policy, direct-vs-gateway decision (*inferred*), route preflight against an existing 100.73/16 route.

### Option B: embedded NetBird in brev-cli, on-demand helper plus ProxyCommand

brev-cli links `client/embed` (netstack, unprivileged, no TUN, route, DNS or firewall change, verified by strace). `brev nb-proxy %h %p` connects to `~/.brev/netbird/agent.sock`, spawns `brev nb-agent` under a pid-file flock when absent, sends `CONNECT <ip> <port>` and relays stdio. The agent runs `embed.New` once per user@machine (`ConfigPath`, `StatePath`, `BlockInbound: true`, lazy off, `WireguardPort: &0`, `NB_DISABLE_NAT_MAPPER`, `NB_WG_KERNEL_DISABLED`), a 0600 socket with a uid check, 30-minute idle exit, and never execs. nb-proxy never calls `embed.New`, so two engines cannot collide on one key (management replaces the Sync channel on re-login, `updatechannel.go:78-80`; the login filter bans after 30 logins in 5 min). The prototype in the checkout (`pkg/cmd/nbproxy/nbproxy.go:94-108`, an engine per ProxyCommand with a persisted setup key) is replaced. sshd plus the certificate stays the authentication boundary; the GA entry is always written as `<alias>-ga` and is the kill switch.

First run:

```
Fresh macOS laptop (Apple Silicon), nothing installed except brev. Timings in brackets are machine time; the two local measurements come from the feasibility report (Start 17 ms, peer Connected 0.21 s on a LAN management), the WAN figures are estimates derived from the RPC sequence (management TLS dial, 4 login RPCs over two connections, Sync, signal, relay, then relay-first peer setup, conn.go:219). Brev service hostnames are illustrative (inferred).

me@mbp ~ % brew install brevdev/homebrew-brev/brev
==> Pouring brev-0.7.x.arm64_sonoma.bottle.tar.gz          (81 MB with the embedded client; 52 MB today)

me@mbp ~ % brev login

   ▸    Starting Login

Logging in with email me@nvidia.com
Press enter to continue or type a different email:
Opening https://brev.nvidia.com/cli-login?... in your browser
[waiting for browser login, 0:24 human time]
Logged in as me@nvidia.com, org research-lab

me@mbp ~ % brev ls
You have 2 instances in Org research-lab
 NAME         STATUS   BUILD      SHELL  ID                 MACHINE       GPU
 train-a100   RUNNING  COMPLETED  READY  env-2f7c1d9e4b0a   g5.12xlarge   A100 x1
 infer-l4     RUNNING  COMPLETED  READY  env-91ab03c7e2f4   g6.xlarge     L4 x1

me@mbp ~ % brev nb-ssh train-a100
This device is not enrolled in the Brev network yet.
Enroll "mbp.local" as device brev-me-mbp? Nothing is installed, no admin rights are needed,
a helper process runs while you use brev and exits after 30 minutes idle. [Y/n] y
[0.3s] EnrollDevice: device 7c1a9f2e-...-c0de, management netbird.brev.nvidia.com
[1.9s] starting helper (brev nb-agent, pid 48213) ... peer registered, mesh ip 100.73.188.41, management connected
[2.2s] ConfirmDeviceEnrollment: ok
Enrolled. Identity: ~/.brev/netbird (0700). Revoke with `brev tunnel revoke` or from the console.
[3.1s] Refreshing SSH config ... 2 instances, 2 with a NetBird target
Resolved SSH target: ubuntu@100.73.21.8:22 via "/opt/homebrew/bin/brev" nb-proxy 100.73.21.8 22
[3.9s] (mint-cert: cache miss, IssueEnvironmentSSHCertificate 0.6s; nb-proxy -> agent: peer 100.73.21.8 connected after 0.4s, relayed, upgrading to p2p)
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 6.8.0-1012-aws x86_64)
Last login: Thu Oct  9 07:02:11 2026 from 100.73.3.2
ubuntu@train-a100:~$ nvidia-smi -L
GPU 0: NVIDIA A100-SXM4-40GB (UUID: GPU-5f3e...)
ubuntu@train-a100:~$ exit
logout
Connection to 100.73.21.8 closed.

me@mbp ~ % brev tunnel status
Device      brev-me-mbp  7c1a9f2e-...-c0de   enrolled 2026-10-09 07:01 (org research-lab)
Helper      running, pid 48213, idle 0m 12s, exits after 30m idle      log: ~/.brev/netbird/agent.log
Management  connected  netbird.brev.nvidia.com    mesh ip 100.73.188.41    signal ok   relay ok
Peers       train-a100   100.73.21.8   connected  p2p      last handshake 9s ago
            infer-l4     100.73.21.9   connected  relayed  last handshake 3s ago
```

Daily:

```
me@mbp ~ % brev shell train-a100
Resolved SSH target: ubuntu@100.73.21.8:22 via "/opt/homebrew/bin/brev" nb-proxy 100.73.21.8 22
[1.7s: helper exited overnight (idle), nb-proxy spawned it; Start ~0.9s WAN, peer connect 0.4s; mint-cert cache miss 0.4s]
ubuntu@train-a100:~$ git pull                       (agent forwarding works: ForwardAgent yes, unchanged)
Already up to date.
ubuntu@train-a100:~$ exit
Connection to 100.73.21.8 closed.

me@mbp ~ % brev exec train-a100 -- nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader
[0.15s: ControlMaster socket ~/.ssh/brev-control-<hash> still alive (ControlPersist 10m); no ProxyCommand spawned, mint-cert cache hit]
97 %

me@mbp ~ % brev port-forward train-a100 -p 8888:8888
Setting up local forward: localhost:8888 -> train-a100:8888
[0.2s: ssh -T -L 8888:127.0.0.1:8888 train-a100 -N, multiplexed over the same master]
^C

me@mbp ~ % brev open train-a100
 checking if your instance is ready... Instance is ready. Opening VS Code 🤙
[VS Code Remote-SSH spawns its own `ssh train-a100` from ~/.ssh/config: same Match exec mint-cert, same ProxyCommand; it shares the one helper; VS Code's connection is its own master]

me@mbp ~ % brev copy ./data.tar train-a100:/home/ubuntu/data.tar
✓ Successfully copied ./data.tar → train-a100:/home/ubuntu/data.tar (3.212s)
[rsync -e ssh over the multiplexed master; throughput is bounded by the overlay path, p2p when ICE succeeds, relay otherwise]

me@mbp ~ % brev shell infer-l4
Resolved SSH target: ubuntu@100.73.21.9:22 via "/opt/homebrew/bin/brev" nb-proxy 100.73.21.9 22
[0.6s: helper warm, peer already connected (eager mode), new master: mint-cert cache miss for env-91ab 0.3s + SSH handshake]
ubuntu@infer-l4:~$ exit

me@mbp ~ % ssh train-a100                           (plain OpenSSH, scp, rsync, mosh-less tools all work the same way)
ubuntu@train-a100:~$ exit

me@mbp ~ % brev tunnel status
Helper      running, pid 48213, idle 1m 03s, 1 session open (VS Code)
Management  connected   mesh ip 100.73.188.41
Peers       train-a100   100.73.21.8   connected  p2p
            infer-l4     100.73.21.9   connected  p2p

me@mbp ~ % brev shell train-a100 --transport ga     (explicit fallback; also what `brev shell` does by itself when the helper reports MGMT_UNREACHABLE)
Using the gateway path (train-a100-ga)
Resolved SSH target: ubuntu@a1b2c3.awsglobalaccelerator.com:32011
ubuntu@train-a100:~$ exit
```

Failures:

```
# 1. Helper not running (normal after 30 min idle). Transparent: nb-proxy spawns it.
me@mbp ~ % BREV_NB_DEBUG=1 brev shell train-a100
Resolved SSH target: ubuntu@100.73.21.8:22 via "/opt/homebrew/bin/brev" nb-proxy 100.73.21.8 22
[nb-proxy] agent.sock: connection refused; took agent.pid lock; spawned brev nb-agent pid 51222 (setsid, stdio -> agent.log)
[nb-proxy] agent ready after 1.3s; CONNECT 100.73.21.8 22 -> OK after 0.5s (peer connected, relayed)
ubuntu@train-a100:~$

# 2. VM stopped. The peer is still in the map but offline (or gone, if Brev removes stopped VMs' peers: inferred).
me@mbp ~ % brev shell train-a100
Resolved SSH target: ubuntu@100.73.21.8:22 via "/opt/homebrew/bin/brev" nb-proxy 100.73.21.8 22
brev: train-a100 (100.73.21.8) is in your network but offline (no handshake for 15s; last seen 42m ago)
kex_exchange_identification: Connection closed by remote host
Connection closed by UNKNOWN port 65535
Connection failed, checking instance status...
instance train-a100 is not running, please start it with: brev start train-a100

# 3. Policy missing: the VM is not in this device's network map (org policy does not include the device group, or the instance was just created and the map has not propagated).
me@mbp ~ % brev shell train-a100
brev: 100.73.21.8 is not in this device's network map (device brev-me-mbp, 2 peers visible). The org policy may not grant this device access; run `brev refresh`, then ask an org admin. Falling back: brev shell train-a100 --transport ga
kex_exchange_identification: Connection closed by remote host
Connection failed, refreshing SSH config and retrying...
Resolved SSH target: ubuntu@100.73.21.8:22 via "/opt/homebrew/bin/brev" nb-proxy 100.73.21.8 22
brev: 100.73.21.8 is not in this device's network map ...
brev shell failed. If the above SSH error is unclear, try running 'brev refresh' and reconnecting.
me@mbp ~ % brev shell train-a100 --transport ga
Using the gateway path (train-a100-ga)
ubuntu@train-a100:~$

# 4. Management unreachable (captive portal, corporate firewall blocking Brev's management host, outage). The pre-exec health check catches it and falls back by itself.
me@mbp ~ % brev shell train-a100
NetBird transport unavailable: management netbird.brev.nvidia.com unreachable after 20s (helper log: ~/.brev/netbird/agent.log). Using the gateway path (train-a100-ga).
Resolved SSH target: ubuntu@a1b2c3.awsglobalaccelerator.com:32011
ubuntu@train-a100:~$
   # If the user runs plain `ssh train-a100` there is no pre-check: after 20s nb-proxy prints
   # "brev: could not connect to the Brev network (management unreachable). Try: ssh train-a100-ga" and OpenSSH prints
   # "Connection timed out during banner exchange" (ConnectTimeout 30 covers the handshake on a ProxyCommand connection).

# 5. Device revoked (brev tunnel revoke from another machine, console, or Brev idle sweep). Management answers PermissionDenied; embed.Start fails permanently (connect.go:350-360).
me@mbp ~ % brev shell train-a100
brev: this device's network identity was revoked or deleted (management: permission denied). Run `brev tunnel enroll` to enroll again, or use --transport ga.
me@mbp ~ % brev tunnel enroll
Enroll "mbp.local" as device brev-me-mbp? [Y/n] y
[2.0s] enrolled, new mesh ip 100.73.188.57       (new peer, new IP; refresh rewrites nothing on the laptop side because HostName is the VM's IP)

# 6. Logged out of Brev (token missing or expired, session key lifetime 24h inferred). The overlay still works; the certificate hook does not.
me@mbp ~ % ssh train-a100
brev: not logged in. Run `brev login` and retry.          (mint-cert, cmd.go:360 no-login store; Match block does not apply)
ssh: Could not resolve hostname train-a100: nodename nor servname provided, or not known
me@mbp ~ % brev shell train-a100
   ▸    Starting Login                                       (loginCmdStore prompts before anything else)

# 7. Identity copied to a second machine (someone restored ~/.brev from a backup). Both helpers fight for the same pubkey; management replaces the Sync channel on every login (updatechannel.go:78-80).
me@mbp ~ % brev shell train-a100
brev: another machine is using this device identity (management closed our session 6 times in 3 minutes). Helper stopped. Run `brev tunnel revoke` and then `brev tunnel enroll` on the machine you keep.

# 8. Two sessions race to start the helper (brev shell and brev port-forward to different VMs at once). One wins the agent.pid flock, the other waits for the socket.
me@mbp ~ % brev port-forward infer-l4 -p 6006:6006 & brev shell train-a100
[nb-proxy 51230] took agent.pid lock; spawned brev nb-agent pid 51233
[nb-proxy 51231] agent.pid held by 51230; waiting for agent.sock ... ready after 1.2s
```

Required changes. Backend: `EnrollDevice{device_id, name, platform, cli_version} -> {management_url, setup_key, device_id}` (re-callable), `ConfirmDeviceEnrollment{device_id, peer_public_key, mesh_ip}`, `RevokeDevice`, `ListDevices`; one-off keys via `POST /api/setup-keys` (`usage_limit 1`, `expires_in 86400`, `auto_groups [brev-devices-<org>]`, `openapi.yml:1264-1305`); revocation is `DELETE /api/peers/{id}` plus key revocation; device table keyed by pubkey; per-user cap and last_seen sweep; console revoke; `EnvironmentNetworkInfo.mesh_ip_address` (`environment.pb.go:9260-9269`) and `Port.server_port` confirmed. The AddNode stopgap is staging only. brev-cli: go.mod on a tagged release, Go 1.26, three replaces, CI pins; `pkg/nbtunnel`; hidden `nbagent` and `nbproxy`; `brev tunnel enroll|status|stop|revoke`; `SSHCertRequiredTemplateNB` = V3 (`sshconfigurer.go:397-437`) plus `ProxyCommand` and `ConnectTimeout 30`, with the V3 entry kept as `<alias>-ga`; mesh plumbing in `refresh/sshaccess.go`; timeouts read from `ssh -G` (`shell.go:222`); logout revoke-then-wipe and `credentials.json` 0600 (`pkg/files/files.go:190` writes `os.ModePerm`); NB_* scrub before `sudo netbird up` (`register/netbird.go:27-36`). Alternative: a separate `brev-nbagent` binary downloaded on first enroll (cloudflared precedent, `refresh.go:71-75`) keeps brev-cli on Go 1.25. NetBird: none required; optional `[client]` PRs, discussion first: Start honoring `startCtx` during login (`embed.go:269-331`), `WaitForPeer` plus a probe-free `Peers()`, `Options.Logger` and netstack selection without `os.Setenv`, default `StatePath` beside `ConfigPath`, `management/server` imports out of `embed_test.go`. Ops: topology spike (*inferred*), per-org groups and policy, audit of All-source rules, public DNS and TLS for management, signal, relay and STUN, relay capacity, PostHog flag, privacy notice for peer metadata.

### Option C: NetBird SSH end to end with embedded Dex as the token issuer

VMs run the NetBird SSH server; laptops run the embedded peer registered with a JWT (user-owned, 24 h expiry); brev-cli exchanges the NVIDIA ID token for a Dex ID token at `<mgmt>/oauth2/token` (token-exchange grant, `SkipClientIDCheck` on the connector) and nb-proxy, a clone of `client/ssh/proxy/proxy.go:104-140` with pluggable dial, token and verifier, injects it as the SSH password. EmbeddedIdP already sets `AuthIssuer`, the audiences and `AuthKeysLocation` (`management/cmd/management.go:266-273`) for both the VM JWTConfig (`conversion.go:290-311`) and the management API. Authorization is one `netbird-ssh` policy per VM or org with `authorized_groups` mapping one group per Brev user to OS users.

First run:

```
$ brew install brevdev/homebrew-brev/brev
...
$ brev login
Opening https://brev.nvidia.com/cli-login in your browser...
Waiting for NVIDIA login                                              [0:00:14]
Logged in as m.santos@nvidia.com (org research-lab)
Enrolling this laptop in the Brev network
  token exchange   POST https://netbird.brev.dev/oauth2/token connector=nvidia     [0.3s]
  peer login       brev-msantos-mbp -> 100.73.41.7 (user-owned, expires in 24h)    [1.8s]
  confirm          ConfirmDeviceEnrollment{device_id, peer_public_key}            [0.2s]
  identity         ~/.brev/netbird/config.json (0600), helper socket ~/.brev/netbird/agent.sock
Writing ~/.brev/ssh_config: 2 instances (transport: netbird), 0 nodes
Run 'brev shell <name>' to connect.

$ brev ls
NAME        STATUS    GPU          MESH IP        SSH
gpu-box-1   RUNNING   1x H100      100.73.12.34   netbird (ubuntu)
trainer-7   RUNNING   8x H100      100.73.19.2    netbird (ubuntu)

$ brev shell gpu-box-1
Resolved SSH target: ubuntu@100.73.12.34:22022 via "/opt/homebrew/bin/brev" nb-proxy 100.73.12.34 22022
[brev] helper already running (pid 48122)
[brev] peer gpu-box-1 connected (p2p)                                             [1.6s]
[brev] token minted for m.santos@nvidia.com (valid 10 min), host key verified
ubuntu@gpu-box-1:~$ nvidia-smi -L
GPU 0: NVIDIA H100 80GB HBM3 (UUID: GPU-5e1d...)
ubuntu@gpu-box-1:~$ exit
logout
Connection to 100.73.12.34 closed.

# What the VM logged (journalctl -u netbird on gpu-box-1, visible to Brev ops, not to the user):
# INFO SSH auth granted (index: 3)        user=ubuntu remote=100.73.41.7:52110 jwt_user=CgsxMjM0NTY3ODkwEgZudmlkaWE
# INFO SSH session started                 session=ubuntu@100.73.41.7:52110 jwt_user=CgsxMjM0NTY3ODkwEgZudmlkaWE
# INFO SSH session closed after 41.2s      session=ubuntu@100.73.41.7:52110 jwt_user=CgsxMjM0NTY3ODkwEgZudmlkaWE

[total: ~20 s from 'brev login' to a prompt, of which 14 s is the browser login]
```

Daily:

```
$ brev shell gpu-box-1
Resolved SSH target: ubuntu@100.73.12.34:22022 via "/opt/homebrew/bin/brev" nb-proxy 100.73.12.34 22022
[brev] helper started (pid 51230), peer login with stored key                     [0.9s]
[brev] peer gpu-box-1 connected (relayed, upgrading)                                [2.1s]
[brev] token minted for m.santos@nvidia.com (valid 10 min), host key verified
ubuntu@gpu-box-1:~$ git pull
git@github.com: Permission denied (publickey).
fatal: Could not read from remote repository.
ubuntu@gpu-box-1:~$ # agent forwarding is not supported by the NetBird SSH server; use a deploy key or HTTPS
ubuntu@gpu-box-1:~$ exit
Connection to 100.73.12.34 closed.

$ brev exec gpu-box-1 -- nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader
92 %
[0.4s: ControlMaster hit, no token exchange, no authentication]

$ brev port-forward gpu-box-1 8888:8888
Setting up local forward: localhost:8888 -> gpu-box-1:8888
[brev] direct-tcpip 127.0.0.1:8888 via gpu-box-1 (local port forwarding enabled on the VM)
^C

$ brev open gpu-box-1
Resolved SSH target: ubuntu@100.73.12.34:22022 via "/opt/homebrew/bin/brev" nb-proxy 100.73.12.34 22022
Opening VS Code (Remote-SSH, host gpu-box-1, folder /home/ubuntu)...               [3.2s to window]
[VS Code installs its server over the existing master; its port forwards ride direct-tcpip]

$ brev copy ./dataset gpu-box-1:/workspace/dataset
Using rsync over ssh (ControlMaster)
sending incremental file list
dataset/train.parquet   1.42G 100%  118.3MB/s  0:00:11
Copied in 12.4s

$ brev shell trainer-7
Resolved SSH target: ubuntu@100.73.19.2:22022 via "/opt/homebrew/bin/brev" nb-proxy 100.73.19.2 22022
[brev] peer trainer-7 connected (p2p)                                               [1.3s]
[brev] token minted for m.santos@nvidia.com (valid 10 min), host key verified
ubuntu@trainer-7:~$

# Next morning, 25 h after login: the laptop peer's 24 h login has expired.
$ brev shell gpu-box-1
[brev] peer login expired, re-authenticating with NVIDIA session                     [0.6s]
[brev] peer gpu-box-1 connected (p2p)                                               [1.4s]
ubuntu@gpu-box-1:~$
```

Failures:

```
# 1. VM stopped (peer in the map, not connected)
$ brev shell gpu-box-1
Resolved SSH target: ubuntu@100.73.12.34:22022 via "/opt/homebrew/bin/brev" nb-proxy 100.73.12.34 22022
[brev] waiting for peer gpu-box-1 (100.73.12.34)...                                 [15.0s]
[brev] gpu-box-1 is not connected (last seen 2h 10m ago). Is the instance running? brev ls
kex_exchange_identification: Connection closed by remote host
Connection closed by UNKNOWN port 65535
brev shell failed. If the above SSH error is unclear, try running 'brev refresh' and reconnecting.

# 2. No policy for this user on this VM (teammate's isolated VM, no grant yet)
$ brev shell trainer-7
Resolved SSH target: ubuntu@100.73.19.2:22022 via "/opt/homebrew/bin/brev" nb-proxy 100.73.19.2 22022
[brev] 100.73.19.2 is not in your network: peer not found in network
[brev] you have no SSH grant on trainer-7. Ask its owner: brev grant-ssh trainer-7 m.santos@nvidia.com
kex_exchange_identification: Connection closed by remote host

# 3. Policy exists, OS user not mapped (user asked for root; rule maps the group to ["ubuntu"])
$ brev shell gpu-box-1 --user root
[brev] gpu-box-1 rejected the token for OS user root: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain
[brev] your grant on gpu-box-1 maps to: ubuntu
# VM log: WARN SSH auth denied: user "CgsxMjM0..." not mapped to OS user "root" (index: 3): user not mapped to OS user

# 4. Management unreachable (token exchange and peer login both need it)
$ brev shell gpu-box-1
[brev] token exchange failed: Post "https://netbird.brev.dev/oauth2/token": dial tcp 34.120.8.9:443: i/o timeout (15s)
[brev] cannot authenticate without Brev's network control plane. Retry, or use the gateway path: brev shell --transport gateway gpu-box-1
kex_exchange_identification: Connection closed by remote host

# 5. NVIDIA session expired (24h) or brev logout ran
$ brev shell gpu-box-1
brev: not logged in (NVIDIA session expired). Run: brev login
kex_exchange_identification: Connection closed by remote host

# 6. Helper not running and cannot start (stale socket, port in use, corrupt config)
$ brev shell gpu-box-1
[brev] helper did not answer on ~/.brev/netbird/agent.sock, starting it...
[brev] helper failed to start within 10s. Log: ~/.brev/netbird/agent.log
[brev] last log line: start embedded netbird client: login: rpc error: code = PermissionDenied desc = peer has been deleted
[brev] this laptop was revoked. Run: brev login
kex_exchange_identification: Connection closed by remote host

# 7. Token exchange refused by Dex (connector removed, NVIDIA JWKS unreachable from management)
$ brev shell gpu-box-1
[brev] token exchange failed: 401 access_denied (connector nvidia could not verify the NVIDIA token)
[brev] contact Brev support; your NVIDIA login is valid but the network IdP rejected it
```

Required changes. Backend: EmbeddedIdP (postgres, NVIDIA OIDC connector, token-exchange grant), `--single-account-mode-domain` (engages only with at most one account at startup, `management/server/account.go:270`), `--disable-default-policy`, `regular_users_view_blocked`, `groups_propagation_enabled`; one-way admin re-keying if an external IdP is configured today (`idp/migration/migration.go:62-66`); device RPCs without setup keys; Dex-sub mapping per Brev user; a reconciler writing one group per user and per VM and `netbird-ssh` rules with `ports ["22"]` and `authorized_groups`, refusing All-source, cross-org and empty rules (an empty map grants every account user, `types/account.go:968-970`); `RegistrationCommand` gains the server, SFTP and forwarding flags; sshd on 2222 with the gateway mapping moved before any VM enables the server (the DNAT at `client/internal/engine_ssh.go:31-55` is unconditional; gateway path *inferred*); VM journald shipping. brev-cli: B's dependency cost plus `pkg/nbauth` (exchange client, 5-minute cache), JWT login in the agent, a stdio-server `nb-proxy` with `nbssh.AddJWTAuth` and `nbssh.CreateHostKeyCallback(embed.Client)`, NB template on `Port 22022` without `Match exec`. NetBird: none required; wanted before GA: pluggable `ssh proxy` (`proxy.go:56-72,605-608,619-623`), agent forwarding, DNAT opt-out, `MaxTokenAge` setting (`conversion.go:304-309`). Ops: NVIDIA client registration, `<issuer>/keys` reachable from Isolated VMs, fleet flag and port rollout, map-recompute capacity test.

### Option D: hybrid transport with auto-detection and staged rollout

Every consumer command execs OpenSSH against an alias, so D makes the transport a property of the ssh_config block: `brev refresh` writes `<alias>` (resolved by auto), `<alias>-gw` (always) and the NetBird block only when the backend returned a mesh target and the machine has a live path. `transport.Resolve` orders daemon (LookPath plus `netbird status --json` with `management.url` and `publicKey` matching `enrollment.json`), embedded (enrollment ACTIVE plus socket), gateway. `--transport auto|gateway|netbird-daemon|netbird-embedded` on shell, exec, port-forward, open, copy; explicit values error instead of falling back. One device record with at most one live peer; a mode switch re-enrolls and deletes the previous peer. Stages 0-4 behind `ssh-transport-netbird-cli`, gated by `{transport, fallback_reason}` analytics.

First run:

```
macOS laptop, no NetBird installed, brev-cli with Option D, stage 2 (login offers enrollment). Timings in brackets are estimates derived from measured embed numbers (Start 17 ms, peer Connected 0.21 s on a local management, report line 36) plus real-network RTTs; not measured end to end.

msantos@mbp ~ % brev login
   ▸     Starting Login
Open https://brev.nvidia.com/cli-login?... in your browser and complete NVIDIA sign-in
[0:00 to 0:38, user finishes SSO in the browser; CLI polls GET /token every 2 s]
current organization: nv-research
Use NetBird for SSH to your instances? No sudo, nothing installed, revocable with 'brev tunnel revoke'. [Y/n] y
Enrolling this device (mode: embedded)
  device    brev-msantos-mbp  id 3f6c1a2e-...                  ~/.brev/netbird/device_id
  EnrollDevice            -> management https://mgmt.brev.example, one-off setup key     [0.4s]
  starting helper         brev nb-agent, socket ~/.brev/netbird/agent.sock                [0.1s]
  peer registered         100.73.41.17  management connected, signal connected           [1.6s]
  ConfirmDeviceEnrollment ok (peer public key bound to this device)                      [0.3s]
Enrollment saved: ~/.brev/netbird/enrollment.json (0600)
Refreshing SSH config
  my-vm         netbird-embedded   100.73.12.5:22     fallback alias my-vm-gw
  shared-a100   netbird-embedded   100.73.19.8:22     fallback alias shared-a100-gw
  legacy-box    gateway            no mesh target returned for this instance
brev has been refreshed                                                                   [1.1s]
Transport: auto -> netbird-embedded (no NetBird daemon on this machine). Details: brev tunnel status

msantos@mbp ~ % brev shell my-vm
Resolved SSH target: ubuntu@100.73.12.5:22 via "/usr/local/bin/brev" nb-proxy 100.73.12.5 22
[mint-cert: cache miss, IssueEnvironmentSSHCertificate 0.6s; nb-proxy: agent already up, peer my-vm connecting -> connected (relayed) 2.1s; sshd banner at 2.9s]
ubuntu@my-vm:~$ exit
logout
Connection to 100.73.12.5 closed.

Linux workstation variant, already registered as a Brev node, now attached as a client (daemon mode):

msantos@ws:~$ brev register --client-only
NetBird daemon found: netbird 0.81.0, profile brev-node, management https://mgmt.brev.example, status Connected, peer 100.73.44.9
This machine is registered as node "ws-lab" (device 9a1d...). Attach its existing NetBird peer as your SSH client? [Y/n] y
  EnrollDevice{existing_peer_public_key}  -> device record created, no new key           [0.4s]
  policy                                   brev-devices-nv-research -> vms-nv-research tcp/22 (backend)
Enrollment saved: ~/.brev/netbird/enrollment.json (mode daemon)
Refreshing SSH config
  my-vm         netbird-daemon     100.73.12.5:22     fallback alias my-vm-gw
brev has been refreshed                                                                   [0.9s]
Transport: auto -> netbird-daemon

msantos@ws:~$ brev shell my-vm
Resolved SSH target: ubuntu@100.73.12.5:22
[mint-cert cache miss 0.5s; daemon peer activation (lazy connection) 1.4s; prompt at 2.3s]
ubuntu@my-vm:~$

Fresh Linux laptop choosing daemon mode explicitly (one sudo prompt):

msantos@laptop:~$ brev tunnel enroll --mode daemon
NetBird daemon not installed. The daemon adds a wt0 interface, a route for 100.73.0.0/16, resolver entries for the Brev DNS domain and /etc/ssh/ssh_config.d/99-netbird.conf. Install it? [y/N] y
[sudo] password for msantos:
  curl -fsSL https://pkgs.netbird.io/install.sh | sh                                      [41s]
  netbird service installed and started (/var/run/netbird.sock)
  EnrollDevice(mode: daemon)   -> one-off setup key                                       [0.4s]
  netbird up --profile brev -k **** -m https://mgmt.brev.example -n brev-msantos-laptop --disable-server-routes --block-inbound   (run as msantos, no sudo)
  Connected                                                                                [2.7s]
  netbird status --json: daemonStatus=Connected management.url=https://mgmt.brev.example netbirdIp=100.73.47.3
  ConfirmDeviceEnrollment ok
Enrollment saved (mode daemon). Undo with: brev tunnel disable
```

Daily:

```
msantos@mbp ~ % brev ls
NAME          STATUS   BUILD  SHELL  ID          MACHINE      GPU
my-vm         RUNNING  -      ready  env_01J9..  g6.2xlarge   1x L4
shared-a100   RUNNING  -      ready  env_01J8..  p4d          8x A100

msantos@mbp ~ % brev shell my-vm
Resolved SSH target: ubuntu@100.73.12.5:22 via "/usr/local/bin/brev" nb-proxy 100.73.12.5 22
[auto probe: LookPath(netbird) miss 0ms, enrollment.json ACTIVE, socket ping 2ms; new ControlMaster: mint-cert cache hit 40ms, peer already connected (P2P), prompt at 0.8s]
ubuntu@my-vm:~$ nvidia-smi -L
GPU 0: NVIDIA L4 (UUID: GPU-6f1e...)
ubuntu@my-vm:~$ exit

msantos@mbp ~ % brev exec my-vm "nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader"
[ControlMaster socket ~/.ssh/brev-control-<hash> alive (ControlPersist 10m): no mint-cert network call, no new nb-proxy, 0.2s]
3 %

msantos@mbp ~ % brev port-forward my-vm -p 8888:8888
Setting up local forward: localhost:8888 -> my-vm:8888
[ssh -T -L 8888:127.0.0.1:8888 my-vm -N, multiplexed over the master, 0.2s; stays until Ctrl-C]
^C

msantos@mbp ~ % brev open my-vm
Instance is ready. Opening VS Code
[VS Code Remote-SSH reads alias my-vm from ~/.ssh/config Include ~/.brev/ssh_config; its ssh runs the same Match exec hook (cache hit) and ProxyCommand nb-proxy; server bootstrap over the relay unchanged; ~4s to a window]

msantos@mbp ~ % brev copy ./data.tar my-vm:/home/ubuntu/
Successfully copied ./data.tar -> my-vm:/home/ubuntu/ (4.2s)
[rsync -e ssh over alias my-vm, multiplexed; throughput bounded by the P2P or relay path, 120 MB at ~30 MB/s here]

msantos@mbp ~ % brev shell --transport gateway shared-a100
Resolved SSH target: ubuntu@a1b2c3d4.ga.brev.example:20118     (inferred GA hostname shape)
[today's path, 1.1s]
ubuntu@shared-a100:~$ exit

msantos@mbp ~ % brev tunnel status
Transport (auto):  netbird-embedded
Reason:            no NetBird daemon on PATH; device enrolled 2026-10-09 09:14 (mode embedded)
Device:            brev-msantos-mbp  3f6c1a2e  peer 100.73.41.17  state ACTIVE  (checked 4m ago)
Helper:            running  pid 48121  idle 0s  relays 2  ~/.brev/netbird/agent.sock
Management:        https://mgmt.brev.example  connected    Signal: connected    Relays: 2/2
Instances:
  my-vm          100.73.12.5:22    connected (P2P)        netbird-embedded   alias my-vm (fallback my-vm-gw)
  shared-a100    100.73.19.8:22    connected (relayed)    netbird-embedded   alias shared-a100
  legacy-box     no mesh target                           gateway            alias legacy-box
Kill switch:       my-vm-gw, shared-a100-gw written; 'brev tunnel set-default gateway' forces it
```

Failures:

```
1. VM stopped (Brev knows): unchanged from today, no transport involved.
msantos@mbp ~ % brev shell my-vm
instance my-vm is not running, please start it with: brev start my-vm

2. VM reported RUNNING but its NetBird peer is offline (netbird client on the VM down):
msantos@mbp ~ % brev shell my-vm
Resolved SSH target: ubuntu@100.73.12.5:22 via "/usr/local/bin/brev" nb-proxy 100.73.12.5 22
brev nb-proxy: peer 100.73.12.5 (my-vm) is in this device's network map but did not reach Connected within 30s (last seen 2h ago)
kex_exchange_identification: Connection closed by remote host
Connection closed by UNKNOWN port 65535                                                   [30.4s]
brev: transport netbird-embedded unavailable for my-vm (peer-unreachable), using gateway
Resolved SSH target: ubuntu@a1b2c3d4.ga.brev.example:20123
ubuntu@my-vm:~$                                                                            [+1.2s]
(the gateway path reaches sshd through the Brev gateway peers, so a VM whose own netbird client is down still fails there; shown as success only when the VM's client is up and the laptop path alone was broken)

3. Policy missing (VM not in the laptop's map; the map holds only peers that share an enabled rule, account.go:892-949):
msantos@mbp ~ % brev shell new-vm
brev: transport netbird-embedded unavailable for new-vm (not-in-map: 100.73.23.4 is not in this device's NetBird network map; backend policy_state for env_01K1.. = NONE), using gateway
Resolved SSH target: ubuntu@a1b2c3d4.ga.brev.example:20131                                [probe 3ms, no 30 s wait: the map check happens before any dial]
ubuntu@new-vm:~$

4. Management unreachable at helper cold start (laptop on a network that blocks the management host; existing tunnels would keep working, so this only bites when the helper has to start):
msantos@mbp ~ % brev shell my-vm
Resolved SSH target: ubuntu@100.73.12.5:22 via "/usr/local/bin/brev" nb-proxy 100.73.12.5 22
brev nb-proxy: helper start failed (mgmt-unreachable): login: dial tcp 203.0.113.10:443: i/o timeout; gave up after 20s
kex_exchange_identification: Connection closed by remote host                              [20.2s]
brev: transport netbird-embedded unavailable (mgmt-unreachable), using gateway
Resolved SSH target: ubuntu@a1b2c3d4.ga.brev.example:20123
ubuntu@my-vm:~$

5. Helper not running and enrollment revoked by an admin (peer deleted in management; Login returns PermissionDenied, auth.go:225-231):
msantos@mbp ~ % brev exec my-vm "hostname"
brev nb-proxy: helper start failed (revoked): login: rpc error: code = PermissionDenied
brev: this device's NetBird enrollment is no longer valid; run 'brev tunnel enroll' to re-enroll. Using gateway for this command.
my-vm

6. Daemon mode, user switched the daemon to another account (profile switch runs Down on the Brev profile, up.go:335-346, server.go:1375-1428):
msantos@ws:~$ brev shell my-vm
brev: transport netbird-daemon unavailable (daemon active profile 'corp', management https://api.netbird.io, expected https://mgmt.brev.example), using gateway. Switch back with: netbird profile select brev
Resolved SSH target: ubuntu@a1b2c3d4.ga.brev.example:20123
ubuntu@my-vm:~$

7. Explicit transport that is not available (no silent fallback):
msantos@mbp ~ % brev shell --transport netbird-daemon my-vm
brev: --transport netbird-daemon is not available on this machine: netbird not found on PATH. Options: brev tunnel enroll --mode daemon, or --transport auto

8. Logged out (session key expired after 24 h, inferred lifetime): the Match exec hook fails before any transport runs.
msantos@mbp ~ % brev shell my-vm
Please log in: run 'brev login'
(brev shell uses the login store and prompts before exec; a bare `ssh my-vm` from another tool prints "brev: not logged in" from the hook, falls through to the static-key Host block on the same NetBird target, and sshd answers Permission denied (publickey); the NetBird block never routes to the gateway host by itself)
```

Required changes. Backend: B's DeviceService plus `GetDeviceEnrollment -> {state, mode, peer_public_key, mesh_ip, policy_state}`, `EnrollDevice.mode` and `existing_peer_public_key`, previous-peer deletion in Confirm, `EnvironmentNetworkInfo.device_mesh_access NONE|ALLOWED`. brev-cli: B plus `pkg/transport`, `--transport` with `BREV_SSH_TRANSPORT` and `brev tunnel set-default`, three-block templates, node-attach in stage 1, `brev tunnel enroll|status|disable|revoke`, ControlMaster on the node template. NetBird: none required; B's five PRs plus a per-profile `99-netbird.conf` opt-out. Ops: B plus stage gates (fallback under 2 percent over two weeks, p95 cold shell under 6 s), nports kept until stage 3.

## 4. Recommended path: B with grafts

NetBird carries bytes; sshd with the 5-minute certificate authenticates. Grafts, with source:

1. Per-target map check before exec (D): consumers ask the agent `STATUS`; a VM not in the map falls back to `<alias>-ga` in milliseconds, with the backend `policy_state` field naming a missing grant without a dial.
2. Fallback inside nb-proxy (persona judge): refresh passes the GA host and port as extra ProxyCommand arguments; nb-proxy relays to the overlay when `CONNECT` answers within 5 s (10 s when spawning), else to the GA endpoint with one stderr line, so VS Code, plain `ssh`, scp and rsync inherit it.
3. Bounded peer wait (C): about 10 s, then "in your network but offline (last seen ...)" and the existing instance-status check.
4. `brev tunnel status` doctor view (D): transport decision and reason, device state, helper, management/signal/relay, per-instance mesh target, map membership, connection type and alias.
5. Explicit `--transport netbird|ga` never falls back silently; only `auto` does (D). `BREV_SSH_TRANSPORT` and `brev tunnel set-default` for pinning an IDE.
6. Enrollment offered at the end of `brev login`, `--approve` for `bak-` API-key runs, replacing `brev nb-ssh` once consumers switch behind the flag (D, C); B's prompt wording, no vendor name on the default path.
7. `{transport, fallback_reason}` via the existing `TrackEvent` path (`shell.go:150-156`) gating stages opt-in, login prompt, gateway-as-fallback-only (D).
8. Refresh-time selection as well as pre-exec (A): the NB block is written only when enrollment is ACTIVE and a mesh target exists, one stderr line per instance left on the gateway.
9. ControlMaster on the external-node NB template (D); node entries have none today (`sshconfigurer.go:57-82`).
10. `brev ls` columns MESH IP and transport, and the no-grant message naming the exact `brev grant-ssh` command (C).
11. A detected native daemon is named in `brev tunnel status`; brev never runs `netbird up` against it (A).
12. Security grafts: console revoke and the last_seen sweep in stage 1, since setup-key peers never expire (`peer.go:804-808`); `credentials.json` 0600 and `~/.brev/netbird` 0700; a continuous check for All-source rules; previous-peer deletion keyed by `device_id`; a replaced Sync channel treated as a theft signal; certificate `KeyId` set to the Brev user ID so sshd's log names the user.
13. Later, with revocation scoped to peers the device created: a daemon transport for machines that already ran `brev register`, via `EnrollDevice{existing_peer_public_key}` (D).

### MVP, flagged

Flag `netbird-transport-cli` (PostHog, as `ssh-cert-required-cli`, `analytics/posthog.go:76-94`), default off; Linux amd64 and macOS; environments only.

- Phase 0, Brev infra (1 week): policy A (`brev-devices-<org>` to `brev-vms-<org>` tcp/22, unidirectional) or policy B (devices to gateway overlay IP:nport, requires the gateway to bind its overlay address, *inferred*); staging management with one VM; OSS validator confirmed; All-source rules audited.
- Phase 1, backend (2-3 weeks): the five device RPCs with `policy_state`; one-off keys into `brev-devices-<org>`; device table by pubkey; cap and sweep; console revoke; mesh fields beside the GA host and port.
- Phase 2, brev-cli (3-4 weeks, 4-5 PRs under 400 lines): go.mod and CI, or the separate helper binary; `pkg/nbtunnel`; `nb-agent` and `nb-proxy` with in-proxy GA fallback and bounded waits; `brev tunnel` verbs; NB template plus `<alias>-ga`; map pre-check; `--transport`; timeouts from `ssh -G`; logout order; env scrub; analytics event; tests and e2e on Linux and macOS.
- Phase 3, hardening (2-3 weeks): host-key pinning from a Brev-published sshd key or host CA with a rewritten `~/.brev/known_hosts` on NB and GA entries alike; lazy connections once `WaitForPeer` lands; JetBrains `useOpenSSHConfig`; external nodes over the overlay; login-time enrollment; default-on per org.
- In parallel: NetBird discussion and the five `[client]` embed PRs.

Exit criteria for default-on: fresh macOS laptop to a shell under 10 s after login with no sudo; cold path under 5 s, warm within 100 ms of GA; flag off returns everyone to GA on the next refresh; console revoke blocks within one Start cycle; fallback rate under 2 percent over two weeks; nothing written outside $HOME.

Stated losses: host keys unchecked until phase 3; a larger binary unless the helper ships separately; Go 1.26 with three replace directives and a module-global circl replace; a per-user helper process; JetBrains, native Windows and the Windows side of WSL stay on the gateway; tenancy rests on group hygiene in one shared account (*inferred*); revocation is Brev's job; the gateway fleet and nports stay until the last org leaves the fallback stage.

## 5. Dealbreakers raised by the judges

Option A:
- The laptop stays an org ExternalNode that any member can list, OpenPort and grant-ssh into until the backend refuses those RPCs on client-labelled nodes (brevconnect C12).
- install.sh under sudo with no version pin; `USE_BIN_INSTALL=true` downloads unsigned binaries with no checksum (`release_files/install.sh:166-204`).
- Without `NB_DISABLE_SSH_CONFIG` the daemon writes a system-wide drop-in with `PasswordAuthentication yes` and `StrictHostKeyChecking no` for every peer (`client/ssh/config/manager.go:193-212`).
- `netbird up --profile brev` runs Down on a connected corporate profile (`client/cmd/up.go:341-350`); today's register reports false success in the `Already connected` and setup-failure cases (`register.go:373-378`).
- No WSL2 or Windows path; a 100.73/16 route with no preflight against an existing overlay prefix (Tailscale's CGNAT range contains it, *inferred*). Opt-in only.

Option B:
- The AddNode stopgap must never reach a flagged-on org.
- The prototype in the checkout (engine per ProxyCommand, setup key persisted, `nbproxy.go:30-35,96-108`) must not ship: a reusable credential at rest and a same-pubkey collision.
- No per-target map pre-check: failure 3 is two 30 s timeouts and a manual `--transport ga`; VS Code and plain `ssh` have no fallback of their own.
- Eager connections to every VM in the org group at helper start under policy A.
- The module-global circl replace (`go.mod:275`) relinks go-git and go-crypto to a 2023 fork; a dependency decision, or a separate helper binary.

Option C:
- No SSH agent forwarding (gliderlabs `session.go:355-356`); `git pull` over a forwarded agent breaks.
- The unconditional DNAT of overlay:22 to 22022 (`client/internal/engine_ssh.go:31-55`) captures the gateway path (*inferred*) to a password-only server (`server.go:898-900`); the sshd port move cannot be flag-gated per user.
- Every new ControlMaster needs a token exchange within a 10-minute iat window; a captive portal or management outage means no new shell.
- The exchanged token is a management API bearer valid on every authorized VM for 600 s (`conversion.go:294-305`, `management.go:266-273`), a regression from the single-VM certificate.
- Every Brev user becomes a NetBird user in one shared account; an empty `authorized_groups` passes the API (`policies_handler.go:259-268`) and grants every account user (`types/account.go:968-970`); single-account mode fails silently with more than one account at startup (`account.go:270`).
- Dex verifies the NVIDIA subject token with `SkipClientIDCheck` (dex `connector/oidc/oidc.go:572-581`), so any NVIDIA application's ID token mints a Brev network token.
- EmbeddedIdP re-keys admin user IDs one way (`idp/migration/migration.go:62-66`); SFTP and port forwarding are host-wide root-set switches.

Option D:
- Attaching a registered node's peer, with Confirm and Revoke deleting peers, deletes the target node's peer on a mode switch or revoke and merges target exposure with client reach on a shared DGX.
- Stage-4 pinning on NetBird blocks with an always-written `-gw` alias at `StrictHostKeyChecking no` and silent auto fallback is a downgrade path.
- The peer-unreachable path blocks 30 s; the daemon installer branch stays out until the embedded path passes stage 2.
- Three transports in every binary and playbook; silent fallback without the analytics event hides breakage; vendor vocabulary on the default path; stage 1 ships manual revoke only.

## 6. Open questions only Brev can answer

1. May a laptop peer dial VM sshd at 100.73.x.y:22 directly, or only a gateway, and does the gateway bind its overlay address today?
2. Will Brev add the device RPCs, and what is the production `RegistrationCommand` shape beyond the `netbird up` prefix?
3. Does the backend populate `ConnectivityInfo.mesh_ip_address`, `EnvironmentNetworkInfo.mesh_ip_address` and `Port.server_port`, and does `Port.hostname` hold the SSH endpoint despite the "HTTP ports" comment (`network.pb.go:614-615`)?
4. Does Brev's management run the OSS validator, which DNS domain, and were any VMs registered with a config predating `ServerSSHAllowed` (defaults to true, `profilemanager/config.go:382-391`)?
5. Is a per-device non-expiring identity revoked by Brev acceptable, or does Brev prefer Ephemeral keys with re-enrollment after 10 minutes offline?
6. Which host-key story replaces `StrictHostKeyChecking no`: a published sshd key per VM, a host CA in the image, or today's posture through the MVP?
7. Will Brev accept Go 1.26, three replace directives, the circl replace and +25-36 MB per binary, or should the helper ship as a separate signed binary?
8. Which authorization applies to OpenPort and GrantNodeSSHAccess for a non-owner, and does AddNode accept a nil `node_spec`?
9. Is `ssh-cert-required-cli` on fleet-wide, and is the 5-minute validity enforced server-side (the CLI never reads `valid_before`, `mintcert.go:63-87`)?
10. Is WSL2 a target, and should headless `bak-` API-key machines enroll?
11. For a later C-style path: what `iss`, `aud`, lifetime and JWKS URL does the NVIDIA KAS ID token carry, and is a NetBird user per Brev user acceptable at all?
