# Prompt: design the best SSH UX for Brev on top of NetBird

You are designing how NVIDIA Brev users should SSH into their machines over NetBird, using
Brev's existing NetBird integration (Brev Connect), Brev's existing auth, and NetBird's SSH
stack. Produce concrete UX options, compare them, and recommend one with an MVP plan.
This is a design exercise: read code and docs, do not implement.

## Repositories and docs

- netbird: github.com/netbirdio/netbird. Relevant: `client/embed` (embeddable client,
  netstack mode, `Dial`, `VerifySSHHostKey`), `client/ssh` (`Handshake`, `AddJWTAuth`,
  `CreateHostKeyCallback`), `client/ssh/client` (the `netbird ssh` client, daemon-coupled),
  `client/ssh/server` (NetBird SSH server: JWT-as-password auth, no public-key auth),
  `client/ssh/detection`, `client/cmd/ssh.go`, `client/wasm/internal/ssh/client.go`
  (SSH over the embedded netstack, the working precedent).
- brev-cli: github.com/brevdev/brev-cli. Relevant: `pkg/cmd/register` (Brev Connect
  registration), `pkg/cmd/enablessh`, `pkg/cmd/grantssh`, `pkg/cmd/deregister`,
  `pkg/cmd/shell`, `pkg/cmd/exec`, `pkg/cmd/portforward`, `pkg/cmd/open`, `pkg/cmd/copy`,
  `pkg/cmd/refresh` (+ `sshaccess.go`), `pkg/ssh/sshconfigurer.go`, `pkg/sshcert`,
  `pkg/cmd/mintcert`, `pkg/cmd/proxy` + `pkg/huproxyclient`, `pkg/cmd/util/externalnode.go`,
  `pkg/auth`, `pkg/config`, `pkg/entity`. The devplane protos are in the Go module cache
  under `buf.build/gen/go/brevdev/devplane/protocolbuffers/go` (look at `external_node.pb.go`,
  `environment.pb.go` for `mesh_ip_address`, `network.pb.go` for `Port`).
- Brev Connect docs: https://docs.nvidia.com/brev/latest/concepts/brev-connect and the
  DGX guides under https://docs.nvidia.com/brev/guides/registered-compute/.
- Prior analysis of Brev's NetBird deployment:
  https://gist.github.com/braginini/94da5ab58cf169feb7a1b4ab692b8a2b
- A feasibility report on embedding NetBird in brev-cli already exists
  (`brev-netbird-embed-ssh-feasibility.md`). Read it if it is available; its verified facts
  are summarised below.

## Facts already established (cite code if you rely on more)

Brev today
- `brev login` authenticates against NVIDIA's OIDC (or a Brev API key). Every SSH session
  is authenticated by a 5-minute SSH certificate minted by `brev mint-cert` from a `Match host
  <alias> exec` hook in `~/.brev/ssh_config`, principal `brev:v1:vm:<id>:login:<user>`.
  The VM's sshd trusts the Brev CA via `authorized_keys` `cert-authority`.
- `brev shell`, `brev exec`, `brev port-forward`, `brev open` (VS Code), `brev copy` all exec
  the system OpenSSH binary against an alias from `~/.brev/ssh_config` (ControlMaster,
  ForwardAgent, StrictHostKeyChecking no, UserKnownHostsFile /dev/null).
- Traffic path today: ssh -> AWS Global Accelerator public address + per-VM "nport" ->
  one of three regional Brev gateway peers -> VM sshd 100.73.x.x:22 over the NetBird overlay.
- Brev self-hosts NetBird management/signal/relay/STUN. ONE shared NetBird account for all
  tenants (100.73.0.0/16). Every VM runs the upstream netbird client joined with a setup key.
  A VM's network map holds only the three gateways by default. Per-machine Network Mode:
  Isolated (default) / Egress only / Meshed, scoped to one org; cross-org never.
- Brev Connect (`brev register "<name>"`): Linux only, needs sudo. Installs the native
  netbird package as a systemd service (pkgs.netbird.io/install.sh), collects a hardware
  profile (GPUs, CPU, RAM, interconnects), calls the AddNode RPC, and runs the returned
  `netbird up --setup-key ... --management-url ...` string. State lives in
  `/etc/brev/device_registration.json`. `brev enable-ssh` writes the Brev CA into
  `authorized_keys` so the machine can be an SSH target; `brev grant-ssh` grants org members
  access; teammates reach it with `brev shell <node>` through a gateway nport, and it is
  listed by `brev ls nodes`. Brev Connect is designed for registering compute you own as a
  TARGET (DGX Station, on-prem GPU boxes), not for a developer laptop as a client.
- The only NetBird credential Brev's API exposes to the CLI is that opaque
  `RegistrationCommand` string. There is no "enroll my laptop as a client device" RPC.
- `EnvironmentNetworkInfo` and `ExternalNode` protos carry `mesh_ip_address`; the CLI already
  calls GetNetworkInfo during `brev refresh` but never reads that field. Whether the API
  populates it is unverified.

NetBird side
- `client/embed` in default netstack mode runs without root, creates no TUN, route, DNS or
  firewall change, and returns a `net.Conn` from `Dial`. `embed.Client` satisfies
  `detection.Dialer` and `nbssh.HostKeyVerifier`; `nbssh.Handshake` accepts any conn and any
  `ssh.ClientConfig`, so SSH over the embedded client needs no upstream change. Caveats:
  `Start` returns before the first network map, ignores the caller's context during login,
  mutates process-global env and logrus; `VerifySSHHostKey` only knows the NetBird-generated
  per-peer key, never an OpenSSH sshd host key.
- Embedding costs brev-cli: Go 1.26, three `replace` directives copied from netbird's go.mod
  (pion/ice fork, wireguard-go fork, cunicu circl), about +25-36 MB per binary.
- The `netbird ssh` CLI client requires the NetBird daemon (JWT token request and host-key
  lookups go over daemon gRPC) and dials over the OS network, so it works only with a native
  installed client (TUN mode).
- The NetBird SSH server (`netbird up --allow-server-ssh`) authenticates with a JWT issued
  by the IdP configured in NetBird management, mapped to OS users through management SSH
  policies (hashed user IDs). It has no public-key or certificate auth. Brev end users are
  not NetBird users today, and all tenants share one account.
- Two engines presenting the same WireGuard key collide at management and signal.
- Setup-key peers never expire; only Ephemeral setup keys get peers deleted (10 min after
  going offline). Revocation otherwise means Brev deleting the peer.

## Options to develop (add others if you find them)

A. Brev Connect as the client enrollment. The laptop runs `brev register` (native daemon,
   TUN mode). `brev refresh` writes `HostName <mesh IP>` for VMs and nodes; OpenSSH dials the
   overlay directly, no ProxyCommand. Consider: sudo and Linux-only today, the laptop showing
   up as an org "node", host routing/DNS changes, macOS support, what `enable-ssh` means on a
   laptop, and whether `netbird ssh` itself becomes usable.
B. Embedded NetBird in brev-cli. `brev nb-ssh <instance>` (later `brev shell`) enrolls the
   device once (via AddNode or a new lighter RPC), persists one identity under `~/.brev`,
   writes a ProxyCommand (`brev nb-proxy %h %p`) entry, and execs OpenSSH as today. A small
   user-level helper holds the single peer. No root, cross-platform.
C. NetBird SSH end to end. VMs run the NetBird SSH server; Brev's IdP becomes NetBird's IdP;
   Brev users (or per-org groups) exist in the NetBird account with SSH policies; `brev shell`
   passes a Brev-issued JWT as the SSH password (`nbssh.AddJWTAuth`), or runs `netbird ssh`
   when a native daemon exists. Analyse token issuer/audience alignment, tenant isolation in
   a shared account, and what Brev's cert CA would still be for.
D. Hybrid with auto-detection. Prefer a native daemon when the machine is a registered node,
   else the embedded client, else today's gateway path; one `--transport` flag and one
   visible fallback line. Define how `brev refresh` chooses templates.

## What to evaluate for every option

- First-run walkthrough as the user sees it: exact commands, prompts, time to first shell.
- Daily walkthrough: `brev shell`, `brev exec`, port-forward, `brev open` with VS Code
  Remote-SSH, `brev copy`, JetBrains Gateway, WSL.
- Platforms: macOS, Linux, WSL, native Windows. Root/sudo required or not.
- Auth and re-auth: when the user logs in again, what the 5-minute cert still guards, how a
  device is revoked on `brev logout` / `brev deregister`, stolen-laptop blast radius.
- Tenancy: which NetBird policies/groups must exist (device -> VM:22 directly, or
  device -> gateway overlay IP:nport), what changes for Isolated/Egress/Meshed.
- Host-key story (today: StrictHostKeyChecking no).
- Failure modes and messages: VM offline, peer not yet connected, policy missing,
  management unreachable, two devices with one identity.
- Required changes, split into Brev backend/API, brev-cli, NetBird upstream (file paths and
  rough size), and ops (policies, groups, IdP config).
- Latency: per-session startup cost of each transport.

## Deliverable

1. A comparison table (options x criteria above).
2. Per-option UX walkthroughs (first run, daily, failure) written as terminal transcripts.
3. A recommendation and an MVP slice that can ship behind a flag, with phases.
4. Open questions that only the Brev team can answer, listed separately.
Keep Brev-infrastructure claims you cannot verify in code marked as inferred. No em dashes,
no hedging narration, under 3000 words plus the transcripts.
