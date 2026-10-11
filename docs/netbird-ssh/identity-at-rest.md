# Embedded tunnel identity at rest

`brev register --embedded` enrolls the device with Brev's NetBird management
and keeps the resulting peer identity under `~/.brev/netbird`. This note
describes what is stored, how it is protected, and what that protection does
and does not give.

## Goal

A device whose Brev login has expired must not be able to start the tunnel
from the files on disk alone. The peer's private key is therefore never stored
in the clear: it is sealed under a secret that only an authenticated call to
Brev's API returns, so every tunnel start goes through `brev login` state, and
removing the node on Brev makes the stored identity unrecoverable.

No Brev backend change is involved. The flows are the ones brev-cli already
uses: `AddNode` and `GetNode` with the `netbird up --setup-key ...` command in
`ConnectivityInfo.registration_command`, and `RemoveNode`.

## What is on disk

`~/.brev/netbird/` (mode 0700) holds:

| File | Content | Secret |
| --- | --- | --- |
| `tunnel.json` | the identity: node id, device name, management URL, enrollment time, and the sealed keys | sealed part only |
| `state.json` | the embedded client's cleanup state | no |
| `networkmap.pb` | the last network map the client received, written by the client next to the state file | contains TURN credentials from management |
| `tunnel.log` | the embedded client's log | no keys; the setup key appears as an 8 character fingerprint |
| `lock` | the single-engine lock | no |
| `targets.json` | the machines `brev ssh --netbird` resolved, by ssh alias: name, id, overlay address, port, kind, time | no |
| `unlock-*.json` | the unlock credentials on their way from `brev ssh --netbird` to `nb-proxy`, deleted as soon as the proxy reads them or ssh exits | setup key, for the life of one ssh start |
| `device_registration.json` | the Brev registration record | no |

The embedded client runs with an in-memory config (`embed.Options.ConfigPath`
empty), so the `config.json` earlier builds wrote, private key included, no
longer exists. A `config.json` left by an earlier build is deleted at the next
enrollment and never read.

## The seal

The sealed part of `tunnel.json` is AES-256-GCM over a JSON document with the
WireGuard private key and the SSH host key the client generated at
enrollment. The key is derived with HKDF-SHA256:

- secret: the setup key from the node's registration command, canonicalized
  as the 16 bytes of the UUID so case and whitespace do not matter;
- salt: 32 random bytes stored beside the ciphertext;
- info: `brev-cli embedded tunnel identity v1`, a zero byte, the node id;
- associated data: the clear header (version, node id, device name,
  management URL), so an edited header no longer unlocks.

Unlocking reads the identity, fetches the node through `GetNode` with the
current Brev session, parses the setup key out of the registration command,
derives the key and decrypts in memory. The WireGuard key is handed to the
embedded client through `embed.Options.PrivateKey`; the embed package has no
option for a stored SSH host key, so each start generates a fresh one and the
sealed copy is kept for a client that can take it.

## Where the unlock happens

- `brev ssh --netbird` unlocks once in the parent process, while the terminal
  is still its own, so an expired session is reported as a clear message
  rather than a bare `255` from inside the ProxyCommand. It then runs ssh and
  hands the credentials to the `brev nb-proxy` ProxyCommand through a one-shot
  file under the tunnel directory whose path travels in `BREV_NB_UNLOCK`: only
  the path is visible to ssh, its children and the detached master, and the
  file is deleted when the proxy reads it or when ssh exits. Run on its own,
  nb-proxy fetches the credentials with the no-login store: that process must
  never start an interactive login because its stdio belongs to ssh.
- A reconnect while the ssh ControlMaster of a previous session is alive
  (`ControlPersist` is ten minutes) skips the lookups and the unlock: ssh
  multiplexes over the running tunnel and never runs the ProxyCommand. The
  target of each resolved alias is remembered in `targets.json` for that path.
  A live master only proves the master process is up, so reuse without asking
  Brev is bounded: an entry older than ten minutes goes through the Brev lookup
  again (the master is still reused, no engine restarts), and a lookup Brev now
  refuses stops the lingering master.
- The master's nb-proxy holds the identity lock for as long as the master
  lives, so a connection to another machine, or `brev tunnel status`, within
  those ten minutes stops the idle master first (`ssh -O stop`) and waits for
  the lock; a master that still carries an open session keeps it, and the
  error names it.
- `BREV_NETBIRD_TIMING=1` prints the per-phase timing of both processes; the
  breakdown is always written to `tunnel.log`.
- `brev tunnel status` unlocks with the login store, so an expired session
  prompts for a login first.
- `brev register --embedded` seals; `brev deregister` removes the node and the
  directory.

## What it gives

- The directory alone does not yield a usable peer: without a Brev session
  there is no setup key and no unlock.
- `brev deregister`, removal in the Brev console, or a change of the node's
  setup key leave the sealed keys unrecoverable, so a stale copy of the
  identity is dead once the node is gone.
- Nothing is written in the clear: not the keys, not the setup key.

## What it does not give

- The Brev session itself lives in `~/.brev/credentials.json`, with a refresh
  token brev-cli renews silently. A copy of the whole `~/.brev` directory
  taken while that session is valid unlocks the identity until the session
  stops renewing. Tightening that file and revoking tokens on logout are
  brev-cli changes outside this one.
- A user who extracted the private key while it was unlocked keeps a working
  identity until the peer is deleted on the NetBird side. Only management-side
  enforcement (JWT enrollment with peer login expiration) closes that, and it
  needs Brev's management to trust Brev's identity provider.
- A process running as the same user can read the session file and perform
  the unlock itself. That is the ceiling of any client-side scheme.

## Assumption to verify

The scheme relies on `GetNode` returning the same setup key for the lifetime
of the node. Run `brev tunnel registration-command` twice some minutes apart
and compare: a changed key means the identity has to be re-enrolled, which
`brev register --embedded` does when the unlock fails.
