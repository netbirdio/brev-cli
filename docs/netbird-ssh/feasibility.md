# brev-cli SSH over embedded NetBird: feasibility

Scope: `netbirdio/netbird` at 01d828d (go 1.26.0) and `brevdev/brev-cli` at 2f82fb3 (go 1.25.0). Brev infrastructure facts come from the relayed summary of the braginini gist; the gist itself was not reachable from the analysis container, so those facts are marked *inferred*. Everything else is verified against code, and where noted, by running it.

## Verdict

**Feasible, no mandatory NetBird change.** `client/embed` in its default netstack mode runs unprivileged, dials overlay peers through gVisor, and a 157-line `brev nb-proxy` prototype compiled and linked into brev against unmodified netbird. Five small upstream PRs would make the integration cleaner; none block it. The gates are on Brev's side: no API issues a NetBird credential to a client device today, and whether a laptop peer can reach a VM (or a gateway on its overlay address) depends on Brev's policies, which cannot be verified from code.

## Recommended design

Keep OpenSSH as the session engine and swap only the transport. `brev refresh` writes ssh_config entries whose `HostName` is the overlay target and whose `ProxyCommand` is `"<brev>" nb-proxy %h %p`. `nb-proxy` talks over a unix socket to a user-level helper, `brev nb-agent`, which owns one embedded NetBird peer per user@machine (identity persisted under `~/.brev/netbird`) and relays bytes between OpenSSH's pipes and `embed.Client.Dial`. Brev's control plane issues a one-off setup key per device and owns revocation.

Why not an in-process Go SSH client: every brev command that reaches an instance shells out to `ssh <alias>` (`pkg/cmd/shell/shell.go:183-263`, `exec/exec.go:259-282`, `portforward/portforward.go:159-172`, `open/open.go:628-703`, `copy/copy.go:185-273`), so a ProxyCommand swap is invisible to VS Code Remote-SSH, scp/rsync, the mint-cert hook, ControlMaster and ForwardAgent. The in-process variant loses all of those and needs three upstream PRs in SSH/auth code.

## How brev SSH works today

- `brev refresh` writes `~/.brev/ssh_config` (`pkg/ssh/sshconfigurer.go:240-280`); consumers run the system OpenSSH binary against an alias. Entries use the Global Accelerator hostname plus a per-VM nport, or a ProxyCommand (cloudflared, `brev proxy` websocket) (`sshconfigurer.go:357-437`).
- Auth is a 5-minute SSH certificate minted by `Match host X exec "brev mint-cert ..."` (`sshconfigurer.go:377-437`, `pkg/cmd/mintcert/mintcert.go:141-190`). `StrictHostKeyChecking no`, `UserKnownHostsFile /dev/null`, `ControlMaster auto` / `ControlPersist 10m`, `ForwardAgent yes` (`sshconfigurer.go:361-371`).
- `brev register` (Linux, sudo) installs the native netbird package and runs AddNode's `RegistrationCommand` through `sudo bash -c` (`pkg/cmd/register/netbird.go:27-36`). That opaque shell string is the only NetBird credential the Brev API exposes (`external_node.pb.go:817-857`).
- *Inferred*: one shared NetBird account (100.73.0.0/16); VMs are Isolated by default, so a VM's map holds only the three gateway peers; users reach VM sshd through gateway nport.

## What client/embed gives

| Capability | Status | Evidence |
|---|---|---|
| Unprivileged netstack mode | Run as uid 65534: engine up, management and signal connected, overlay listen/dial work | `client/embed/embed.go:186-193`, `client/iface/iface_new_linux.go:16-23` |
| No TUN, route, DNS, firewall or ssh_config change on the host | Verified by strace | `routemanager/manager.go:147,238-243`, `dns/server.go:453-459`, `firewall/create_linux.go:48-62`, `engine_ssh.go:108,223` |
| `Dial`/`DialContext` returning `net.Conn` over gVisor | Verified | `embed.go:377-394` |
| Satisfies `detection.Dialer` and `nbssh.HostKeyVerifier` | Compile-verified | `client/ssh/detection/detection.go:36-38`, `client/ssh/common.go:34-36` |
| `nbssh.Handshake` over any conn with a cert signer in `Auth` | Test passed (gonet conn, `CertChecker` server) | `client/ssh/handshake.go:18-39` |
| Identity persistence | `ConfigPath` persists WG and SSH keys; re-runs log in without sending the setup key; `PrivateKey` alone satisfies `validateCredentials` | `embed.go:139-160,225-240`, `client/internal/auth/auth.go:208-241` |
| SSH server never starts | `ServerSSHAllowed` false for a fresh config; `BlockInbound` stops it regardless | `profilemanager/config.go:308-318`, `engine_ssh.go:57-70` |

Gaps that shape the design:

- `Start` returns before the first network map. A Dial's SYN is dropped until the target peer's ICE or relay path is up (`wireguard-go device/send.go:368`), and gVisor retransmits at 1 s, so an early Dial completes at the next retransmit, not when the peer connects. Measured locally: Start 17 ms, peer Connected at 0.21 s, a Dial issued at 18 ms returned at 1.00 s. Wait for `ConnStatus == Connected` before dialing.
- `Start` ignores the caller's context during management dial and login (`embed.go:276,288,292`; `startCtx` first consulted at `:309`). Measured: 30 s on a 2 s deadline; the login retry loop can run about 2 minutes.
- `VerifySSHHostKey` only compares against the NetBird-generated key that management ships for every peer (`shared/management/networkmap/encode.go:287`), never sshd's. A VM outside the map yields `ErrPeerNotFound`; a VM inside the map yields a hard "host key mismatch" (`common.go:162`).
- Host footprint beyond one UDP socket: the NAT port mapper runs regardless of netstack (`engine.go:657-661`, `NB_DISABLE_NAT_MAPPER`); the kernel WireGuard module probe runs as root (`connect.go:374`, `NB_WG_KERNEL_DISABLED`); an empty `StatePath` falls back to `/var/lib/netbird` (`profilemanager/service.go:456-470`); cloud-metadata HTTP probes at login; QUIC relay over UDP; process-global `NB_*` env vars and global logrus reconfiguration (`embed.go:174-200`). On macOS an MDM plist can override `ManagementURL` (`client/mdm/policy_darwin.go:25`).
- `Status()` runs STUN/TURN probes on every call (`embed.go:493-506`), so it is not a polling primitive.

## Build experiment

Scratch worktree of brev-cli with `require github.com/netbirdio/netbird` (local replace), `go 1.26.0` / `toolchain go1.26.7`, three copied replace directives (wireguard-go, pion/ice, circl) plus dex for a clean tidy, and `go get google.golang.org/genproto@latest cloud.google.com/go@latest`. `go build ./...`, `go vet`, and brev's `pkg/ssh`, `pkg/cmd/shell`, `pkg/cmd/register`, `pkg/sshcert` tests pass.

| Target | Baseline | With embed | Delta |
|---|---|---|---|
| linux/amd64 CGO=1 (release config) | 53,762,672 B | 89,447,992 B | +35.7 MB (+66%) |
| linux/amd64 stripped `-s -w` | 37,477,960 B | 62,772,264 B | +25.3 MB |
| darwin/arm64 CGO=0 | 51,846,114 B | 80,781,106 B | +28.9 MB |
| darwin/amd64 CGO=0 | 54,129,184 B | 84,255,856 B | +30.1 MB |
| Warm relink, linux/amd64 | 3.96 s | 6.20 s | +2.2 s |
| go.mod indirect requires | 107 | ~204 | about +100 |

| Item | Finding |
|---|---|
| Go directive | 1.25.0 -> 1.26.0 is unavoidable (`netbird/go.mod:3`; quic-go v0.62.0 and x/sync v0.23.0 also require 1.26). The raise is automatic on `go get`/`tidy`. brev pins 1.25.0 in 24 workflow files, `Makefile:19,147` and `release.yml:12`; all move. |
| Replace directives | Not inherited by consumers. Build needs exactly 3 (`github.com/pion/ice/v4` placeholder `v4.0.0-00010101000000-000000000000`, `go.mod:98`; fork-only APIs `ice.CandidatePairIDFromSTUN`, `device.CreateOutboundPacket`; rosenpass -> circl mceliece). A 4th (dex) only for plain `go mod tidy`, because `client/embed/embed_test.go:13-17` imports `management/server`. A go.work workspace inherits them instead. |
| Direct bumps via MVS | cobra 1.8.1->1.10.2, viper 1.13.0->1.21.0, afero 1.9.2->1.15.0, testify 1.11.1->1.12.1, jwt/v5, go-version, ssh_config, pflag |
| circl replace | Module-global: brev's go-git/ProtonMail go-crypto now links the 2023 cunicu fork. Tests pass; not security-reviewed. |
| Cross targets | linux/arm64 and windows/amd64 at CGO=0 fail identically on pristine brev (go-nvml); not a netbird regression. CGO=1 linux/arm64 untested (no cross gcc). |
| What links | Zero `management/*` packages. Growth is gvisor (41 pkgs), aws-sdk-go-v2 (52, via `encryption` -> certmagic -> libdns/route53), quic-go (16), pion, rosenpass, gliderlabs/ssh + sftp. |

## Recommended architecture

```
brev shell my-vm
  └─ ssh -t my-vm                      OpenSSH, ~/.brev/ssh_config via Include
       ├─ Match host my-vm exec "brev mint-cert ..."    5-min cert, unchanged
       └─ ProxyCommand "brev" nb-proxy 100.73.x.y 22
            └─ ~/.brev/netbird/agent.sock ──► brev nb-agent   (one per user@machine)
                                                 ├─ embed.Client, netstack, ConfigPath identity
                                                 │    mgmt/signal/relay over TLS, WireGuard over UDP
                                                 └─ Dial(host:port) ──► VM sshd :22            (policy A)
                                                                    or gateway overlay IP:nport  (policy B, inferred)
```

1. **Enrollment record** `~/.brev/netbird/enrollment.json` {device_id, management_url, peer pubkey, mesh IP, gateways}, 0600, written by `brev tunnel enroll` (or on `brev login`) through a new Brev RPC; the setup key is consumed inside enroll and never stored.
2. **`brev nb-agent`** (hidden): flock; `embed.New` with `ConfigPath`, `StatePath`, `BlockInbound: true`, `LazyConnectionEnabled: &false`, `WireguardPort: &0`, `LogOutput` file at warn, `NB_DISABLE_NAT_MAPPER` and `NB_WG_KERNEL_DISABLED` set; `Start` under a hard timeout; 0600 unix socket in a 0700 dir with an `SO_PEERCRED`/`LOCAL_PEERCRED` uid check (deny on unknown identity); line protocol `CONNECT host port` -> `OK` or `ERR <msg>`; waits for the peer to reach Connected before dialing; relays with `util/netrelay`; idle-exit 30 min. It never execs anything, so `NB_*` env mutation stays confined.
3. **`brev nb-proxy`** (hidden): connect to the socket or spawn the agent (`setsid`, `Process.Release`), send CONNECT, relay stdio. Zero bytes on stdout on failure (verified on the prototype); classified hints on stderr. It never calls `embed.New`, so the single-identity invariant is in code.
4. **ssh_config**: a third template = V3 (`sshconfigurer.go:397-437`) plus `ProxyCommand` and `ConnectTimeout 30`, selected when an enrollment exists, the feature flag is on, and the backend returned a mesh target; otherwise the GA entry (fleet-wide kill switch).

The helper belongs in the MVP: two engines presenting one WG key collide (management closes the previous Sync channel, `update_channel/updatechannel.go:78-82`; signal overrides the stream, `signal/peer/peer.go:97-105`; 30 reconnects in 5 min bans the pubkey, `loginfilter.go:67-85`), and ControlMaster multiplexes per alias only, so `brev shell` plus `brev port-forward` to different VMs would spawn two ProxyCommands.

## NetBird upstream changes

None required. Recommended, one small PR each tagged `[client]`, discussion or issue first since each touches the public embed API or env handling:

1. `client/embed/embed.go:276-292`: derive the auth/login context from `startCtx` (or add `Options.LoginTimeout`). ~20 LOC plus test.
2. `client/embed`: `WaitForPeer(ctx, addr netip.Addr) error` on `recorder.SubscribeToStateChanges` (`client/internal/peer/status.go:1362-1372`) with `ConnMgr.ActivatePeer` for lazy peers (`client/internal/dns_peer_activator.go:31-58` is the precedent), plus a probe-free `Peers()` snapshot. ~100 LOC plus tests.
3. `client/embed`: `Options.Logger` (or `QuietLogs`) instead of global logrus (`embed.go:174-184`); select netstack through an internal flag rather than `os.Setenv` (`embed.go:186-200`, read at `client/iface/netstack/env.go:46-67`), or restore the env on `Stop`. ~50 LOC.
4. `client/embed/embed.go:195-200`: default `StatePath` beside `ConfigPath`, or `Options.DisableStatePersistence`, so unprivileged consumers never touch `/var/lib/netbird`. ~15 LOC. Same PR could add options for the NAT mapper and kernel probe.
5. `client/embed/embed_test.go:13-17`: move the `management/server` imports to a separate package or build tag so a consumer's `go mod tidy` no longer needs the dex replaces and the cloud.google.com/go bump; list the three required replaces in `client/embed/doc.go`.

Later, only if Brev wants in-process exec or port-forward: `client/ssh/client/client.go` `DialOptions{Dialer, AuthMethods, HostKeyCallback, SkipDetection}` plus `NewClient(*ssh.Client)` (Dial hard-codes `net.Dialer` at `:322` and `:352`).

## brev-cli changes

- `go.mod`: netbird tag, 3 replaces (+dex for tidy), `go 1.26.0`, genproto/cloud.google.com bumps; CI `go-version` and goreleaser-cross pins to 1.26; ldflag `-X github.com/netbirdio/netbird/version.version=<brev version>` (otherwise `WtVersion` is "development" and fails NBVersion posture checks, `version/version.go:14-25`).
- New: `pkg/nbtunnel` (embed wrapper, enrollment file, bounded `Start`, wait-for-Connected), hidden `pkg/cmd/nbagent` and `pkg/cmd/nbproxy` (registered in `pkg/cmd/cmd.go:383`), `pkg/cmd/tunnel` with `enroll | status | revoke`; `brev logout` revokes best-effort and removes `~/.brev/netbird`.
- `pkg/ssh/sshconfigurer.go`: NB template pair, branch in `makeSSHConfigEntryV2` (`:462-531`) and `makeSSHConfigEntryForNode` (`:93-132`); JetBrains XML (`:785-805`, `UseOpenSSHConfig false`) and WSL (`:258-305`) stay on GA.
- `pkg/cmd/refresh/sshaccess.go:89-153`, `pkg/cmd/util/externalnode.go:93-118`, `pkg/entity/entity.go:287-298`: carry the mesh target (`EnvironmentNetworkInfo.mesh_ip_address`, `environment.pb.go:9268`; `Port.server_port`, `network.pb.go:609`).
- Timeouts: `util/ssh.go:18-22`, `shell.go:187,190`, `exec.go:281`, `open.go:631` read the transport from `ssh -G` (`shell.go:222` already runs it) and use 15-30 s for NB aliases. Add `--transport auto|openssh|netbird` with one visible fallback line.
- `pkg/cmd/register/netbird.go:27-36`: scrub `NB_USE_NETSTACK_MODE`, `NB_NETSTACK_SKIP_PROXY`, `NB_DNS_STATE_FILE` from `cmd.Env` before `sudo netbird up`.
- Tests: nb-proxy stdout-hygiene, socket protocol with a fake dialer, sshconfigurer golden files.

Estimate: 700-1000 LOC, 3-4 engineer-weeks including e2e against a staging management.

## Brev backend and policy changes

- **RPCs**: `EnrollDevice` -> {management_url, setup_key, gateways, nport_range}; `ConfirmDeviceEnrollment{device_id, peer_public_key}` (join on pubkey, not mesh IP, since IPs are reused); `RevokeDevice`; `ListDevices`. Backend calls management REST: `POST /api/setup-keys` with type one-off, `usage_limit 1`, `expires_in 86400` (API minimum, `openapi.yml:1264-1299`), `ephemeral false`, `auto_groups [brev-devices-<org>]`. Revoke = `DELETE /api/peers/{id}` (`openapi.yml:7409`) plus key revocation, because revoking a key never deletes peers. Device table keyed by `setup_key_id -> user`, since management stores `UserID` empty for setup-key peers (`management/server/peer.go:797-808`). Per-user device cap and idle sweep, since OSS management has no peer quota (`loginfilter.go:12-18` throttles a single pubkey only).
- **Policy**, one of (*inferred* topology): (A) `brev-devices-<org> -> vms-<org>` tcp/22 unidirectional: direct dial, VM maps update on every device enroll/revoke (`peer.go:977-981`). (B) `brev-devices -> brev-gateways` on the nport range: only three gateway peers see device churn; requires the gateway service to listen on its overlay IP, unverified. Audit rules with `All` as source: every setup-key peer joins `All` (`peer.go:907-919`).
- `Port.mesh_hostname` on the devplane `Port` (`network.pb.go:607-613`) so refresh never parses `RegistrationCommand`; omitting it is the fleet-wide kill switch.
- Later: `ssh_host_public_key` or a host CA per VM so the NB template can move to `StrictHostKeyChecking yes`.
- Confirm Brev's management uses the OSS validator (never holds peers for approval, `integrated_validator.go:143-162`).

## Security and tenancy

- AGENTS.md daemon-RPC rules do not apply: embed runs no daemon, no ipcauth, no SSH server. Legacy config files without `ServerSSHAllowed` default it to true (`config.go:382-391`), so use a fresh Brev-owned path plus `BlockInbound`. Inbound to the device peer is default-deny (`engine.go:668-670`, `uspfilter/filter.go:1733-1747`); `DisableServerRoutes` is forced (`embed.go:214`).
- Credential at rest after enrollment is only the device WG private key. Setup-key peers never login- or inactivity-expire (`peer.go:797-810,1431-1433`), so revocation depends on Brev deleting the peer. A stolen identity gives L3 reach to what the device group's policies allow; under policy B that equals today's public nport exposure. sshd certificate auth stays the authn boundary: NetBird's SSH server has no public-key handler (`client/ssh/server/server.go:879-900`), and NetBird JWT auth needs management's IdP and NetBird users, which Brev end users are not.
- Tenancy rests on group hygiene in one shared account: a peer's map is exactly the peers it shares an enabled rule with (`types/account.go:892-949`).
- Attribution: `DeviceName = brev-<user>-<host>` plus Brev's device table. Management records laptop LAN prefixes and hardware serial (`management/server/peer/peer.go:141-179`), a privacy item to disclose.
- A Sync stream closed by a newer login of the same pubkey is a theft signal: the agent stops reconnecting and asks for re-enrollment.
- Host keys: unchanged posture in the MVP (`StrictHostKeyChecking no`) on a transport stronger than the public GA endpoint.

## Peer lifecycle

- First run: `EnrollDevice` -> `Start` registers (one-off key consumed, `UsedTimes` 1) -> `Confirm` with pubkey -> identity persisted.
- Later runs: Login with the stored key; the Login RPC carries no setup key (`shared/management/client/grpc.go:650-656`), nothing is consumed. Each `Start` performs two logins (`connect.go:317-318,353`).
- Peer deleted (revoke, sweep, admin): next `Start` gets `PermissionDenied`, nb-proxy prints "run brev tunnel enroll"; re-enrollment gets a new key, a new peer ID and a new IP.
- Optional ephemeral mode: an Ephemeral key deletes the peer 10 min (plus a 1 min cleanup window) after the Sync stream ends; the clock also runs from registration until first connect, and a management restart re-arms it (`ephemeral/interface.go:11`, `ephemeral.go:126-153,200-226`).
- Logout: revoke, stop the agent, delete `~/.brev/netbird`.

## Risks and unknowns

| Risk | Status | Mitigation |
|---|---|---|
| Laptop peer cannot reach the VM (policy) or gateway overlay listener absent | Unverified, load-bearing | Decide A vs B with Brev infra first; nb-proxy dials whatever refresh wrote; spike on staging |
| No credential RPC; production `RegistrationCommand` format unknown | Verified gap | Ship `EnrollDevice` before CLI work |
| Cold start per agent spawn | Code-derived 1-5 s, unmeasured | Agent idle 30 min; `ConnectTimeout 30`; WaitForPeer |
| `Start` ignores ctx; bad URL blocks 30 s to 2 min | Measured | Goroutine + timer + `Stop`; upstream PR 1 |
| Same-pubkey collision | Verified code paths | Single agent, flock, nb-proxy never embeds |
| circl replace downgrades go-git crypto | Verified | Review with Brev; upstream could make Rosenpass optional |
| Peer approval if management-integrations build | Unknown | Confirm validator |
| NAT mapper, kernel probe, `/var/lib/netbird` fallback | Verified | Env vars and `StatePath` in the agent; upstream PR 4 |
| macOS MDM plist override of ManagementURL | Verified code | Detect and warn |
| Replace directives drift per netbird release | Verified | Pin a tag; upstream PR 5 documents the list |

## MVP plan

- **Phase 0, Brev infra (1 week)**: pick policy A or B; verify the gateway overlay listener for B; confirm the validator; staging management with one VM.
- **Phase 1, backend (2-3 weeks)**: Enroll/Confirm/Revoke RPCs, setup-key provisioning, groups and policy, `Port.mesh_hostname`, device cap.
- **Phase 2, brev-cli (3-4 weeks, flag off by default)**: go.mod and CI merge; `nbtunnel`; nb-agent and nb-proxy; `tunnel enroll|status|revoke`; NB template; mesh plumbing; timeouts; logout; env scrub; tests; e2e on Linux and macOS.
- **Phase 3, hardening**: host-key field plus known_hosts, idle sweep, JetBrains `useOpenSSHConfig`, default-on.
- **In parallel**: NetBird discussion and PRs 1-5.

## Open questions for the user

1. Which topology will Brev support: devices -> VM tcp/22 directly, or devices -> gateway on its overlay IP:nport? Does the gateway bind on its overlay address today?
2. Will Brev add a client-device credential RPC, or must the MVP parse `RegistrationCommand` (and what is its production format)?
3. Does Brev's self-hosted management run the OSS validator or management-integrations with peer approval?
4. Is a per-device persisted, non-expiring identity (revoked by Brev) acceptable, or does Brev prefer ephemeral per-session peers?
5. Which host-key story replaces `StrictHostKeyChecking no`: Brev-published sshd keys, a host CA, or keep today's posture for the MVP?
6. Will Brev accept Go 1.26, three replace directives kept in sync with netbird releases, and +25-36 MB per binary?
7. Should NetBird open the discussion for upstream PRs 1-5 now, and should brev pin the first tagged NetBird release on Go 1.26, or a tag cut after they land?
