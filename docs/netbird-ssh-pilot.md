# Test the NetBird SSH pilot

Status: experimental work in progress. Dependency resolution, compilation, and
the full test suite have not completed in the development environment. No live
Brev connection has been verified. Run `go mod tidy` before building this snapshot.

This branch adds an opt-in transport for existing Brev SSH aliases. OpenSSH and
Brev's certificate hook still authenticate the session. One unprivileged helper
owns the NetBird peer and serves concurrent SSH connections over local IPC.

The pilot is for Linux, macOS, and Linux inside WSL. It does not install a native
NetBird service, create a TUN interface, or change host routing and DNS. Native
Windows and JetBrains Gateway are not qualified in this pilot. VS Code must use
the same OS environment and SSH configuration as the CLI.

## Build and run offline tests

Start from this branch of the fork. Go 1.26.7, a C compiler, Git, and OpenSSH are
required. On Debian/Ubuntu the compiler comes from `build-essential`; on macOS,
use the Xcode command-line tools. The existing NVML dependency needs CGO on Linux.

```sh
git clone --branch work/netbird-ssh-pilot https://github.com/netbirdio/brev-cli.git
cd brev-cli
go version
go mod tidy
make fast-build
make test-netbird
./brev tunnel --help
```

The tests use fake transport engines and local sockets. They do not enroll a
NetBird peer or require Brev credentials. They cover concurrent connections,
identity locking, cancellation, target allowlisting, host-key configuration, and
the requirement that ProxyCommand stdout contain only protocol bytes.

Keep the built binary at this path while testing. Configuration records its
absolute path so an IDE does not accidentally invoke an older installed Brev.
Rerun `tunnel configure` after moving the binary.

## Prerequisites for a real connection

1. An existing Brev instance with certificate-based SSH access. Run `brev login`
   and `brev refresh` using the newly built binary. The generated alias must have
   a `brev mint-cert` hook and a plain TCP gateway endpoint. Cloudflared and other
   ProxyCommand gateway aliases are rejected by this pilot.
2. The NetBird management HTTPS URL and an administrator-provided **one-off setup
   key** for a client-device group. Use a dedicated test deployment or approved
   staging group. Do not use `brev register` to enroll the laptop.
3. A directional NetBird policy from that group to the intended target's actual
   SSH TCP port. Do not enable broad account-wide access. The overlay IP and port
   must identify the same sshd reached by the existing Brev alias. Port 22 is an
   example, not an assumption about container or external-node mappings.
4. The target's sshd public host key, delivered through a trusted administrator
   channel. For example, an administrator can read
   `/etc/ssh/ssh_host_ed25519_key.pub` on the target. The file must contain public
   keys, not private keys, certificates, or `known_hosts` entries. A network
   `ssh-keyscan` result alone is not a trusted source.

Production client-device enrollment and host-key publication APIs do not exist
in this repository. This pilot takes those inputs explicitly. It does not reuse
AddNode, parse RegistrationCommand, or claim that it grants Brev SSH access.

## Enroll, configure, and connect

Replace the example management URL, alias `gpu`, overlay address, and key-file
path with values supplied by your administrator.

```sh
export BREV_EXPERIMENTAL_NETBIRD=1
./brev login
./brev refresh

# Bash: read the one-off key without echoing it or putting it in shell history.
read -r -s -p 'NetBird setup key: ' BREV_PILOT_SETUP_KEY
printf '\n'
printf '%s\n' "$BREV_PILOT_SETUP_KEY" | ./brev tunnel enroll \
  --management-url https://netbird.example.com \
  --name my-brev-laptop \
  --setup-key-stdin
unset BREV_PILOT_SETUP_KEY

./brev tunnel configure gpu \
  --address 100.73.1.20:22 \
  --host-key-file /path/to/trusted-gpu-host-key.pub

# Configuration starts in gateway mode, with host verification already enabled.
./brev shell gpu

./brev tunnel use direct
./brev shell gpu
```

The setup key goes to the enrollment subprocess through stdin. It is not stored
in the profile or passed as a command-line argument. NetBird's generated device
identity is stored under `~/.brev/netbird`, separately from a native daemon.
Do not copy this directory to another computer.

`tunnel configure` adds a small Include before Brev's normal SSH configuration.
It preserves the existing certificate hook and gateway endpoint. Both modes
require the supplied sshd host key and certificate authentication. The pilot
disables ControlMaster for configured aliases so an existing connection cannot
silently select a different transport. Other aliases keep their current behavior.

The first direct connection starts the helper. Later connections share that
peer. Helper startup and connection attempts are bounded; a failed connection
does not automatically switch transport. The feature environment variable is
needed for enrollment/configuration and selecting direct mode, not for each
subsequent IDE or ProxyCommand invocation.

## Acceptance checks

```sh
./brev tunnel status
ssh -G gpu | rg '^(proxycommand|stricthostkeychecking|hostkeyalias|userknownhostsfile|controlmaster|controlpath|connecttimeout) '

./brev exec gpu "hostname"
./brev copy ./README.md gpu:/tmp/brev-netbird-readme.md
./brev open gpu

# With a service listening on target localhost:8888:
./brev port-forward gpu -p 8888:8888

# In separate terminals, keep multiple sessions open:
./brev shell gpu
ssh gpu
```

Expected results: `ssh -G` names `nb-proxy` in direct mode, strict host checking is
enabled, and simultaneous sessions remain usable with one helper. VS Code's
Remote-SSH connection uses the same alias and trusted host key. OpenSSH and
`brev exec` must not receive progress messages on their protocol/output stream.

For a command that fails remotely, verify it is executed once:

```sh
./brev exec gpu "printf 'executed once\n'; exit 17"
```

Expect one `executed once` line and a nonzero CLI exit. Brev's global error
handler does not currently preserve every remote process exit code, so do not
expect the CLI's numeric code to be exactly 17.

To exercise a cold start, close test sessions, run `./brev tunnel stop`, and
connect again. The helper restarts automatically. `stop` closes active direct
sessions, so use it only when ready to end them.

To test host-key mismatch, configure a different administrator-provided test
key for the test alias. Both gateway and direct connections must fail with host
verification errors. Restore the real key afterward. Do not disable strict
checking to get a connection through.

## Rollback and local cleanup

```sh
./brev tunnel use gateway
./brev tunnel stop
```

This changes new connections back to the original gateway while retaining host
verification. It does not install or remove a system service. Existing direct
sessions end when the helper stops.

```sh
./brev tunnel forget
```

`forget` selects gateway mode, stops the helper, and removes its local identity.
Host-key pins and the target configuration remain. `brev logout` also cleans up
the default local helper identity before clearing Brev login credentials.

**Remote revocation is manual in this pilot.** Ask the administrator to delete
the peer in NetBird management. Revoking the setup key or deleting local files
does not revoke a stolen copy of the peer identity. Existing sessions and cached
SSH certificates have their own lifetimes. No instant remote-revocation
guarantee is provided by this branch.

## Current boundaries

- Explicit `direct` and `gateway` selection only. No automatic fallback, native
  daemon reuse, or change to NetBird SSH/JWT authentication.
- Alias bindings and host keys are administrator-provided staging inputs. They
  are not backend-signed resource or organization attestations.
- `tunnel status` reports local enrollment/helper state. It does not assert that
  remote policy permits a target or that the peer has not been revoked.
- A stolen logged-in laptop still requires revocation of Brev login credentials
  and the NetBird peer. Production device-bound issuance needs backend work.
- Embedding raises the Go toolchain requirement and includes NetBird's required
  module replacements. In particular, the circl replacement affects the whole
  Go module; it is not isolated to this transport.
- No live deployment or IDE test is implied by passing the offline tests. Use
  the acceptance checks above against your approved staging deployment.
