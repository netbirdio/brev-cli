package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	nodev1connect "buf.build/gen/go/brevdev/devplane/connectrpc/go/devplaneapi/v1/devplaneapiv1connect"
	nodev1 "buf.build/gen/go/brevdev/devplane/protocolbuffers/go/devplaneapi/v1"
	"connectrpc.com/connect"

	"github.com/brevdev/brev-cli/pkg/cmd/register"
	"github.com/brevdev/brev-cli/pkg/config"
	"github.com/brevdev/brev-cli/pkg/externalnode"
	"github.com/brevdev/brev-cli/pkg/nbtunnel"
)

// ErrNotLoggedIn means no Brev session is available to fetch the key that
// unlocks the tunnel identity.
var ErrNotLoggedIn = errors.New("not logged in to Brev; run 'brev login' to use the embedded Brev tunnel")

// EnvUnlock names a one-shot file through which 'brev ssh --netbird' hands
// the unlock credentials to the nb-proxy that ssh spawns for it, so the proxy
// does not repeat the Brev API call the parent just made. Only the path
// travels through ssh's environment; nb-proxy deletes the file as it reads
// it and the parent deletes it after ssh exits, whichever comes first.
const EnvUnlock = "BREV_NB_UNLOCK"

// StashCredentials writes creds to a private one-shot file under dir and
// returns its path, for EnvUnlock.
func StashCredentials(dir string, creds nbtunnel.Credentials) (string, error) {
	data, err := json.Marshal(creds)
	if err != nil {
		return "", fmt.Errorf("encode unlock credentials: %w", err)
	}
	f, err := os.CreateTemp(dir, "unlock-*.json")
	if err != nil {
		return "", fmt.Errorf("create unlock file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("write unlock file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("write unlock file: %w", err)
	}
	return f.Name(), nil
}

// RemoveStash deletes a file StashCredentials created; a file nb-proxy
// already consumed is fine.
func RemoveStash(path string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "warning: remove %s: %v\n", path, err)
	}
}

// CredentialsFromEnv reads and deletes the file a parent brev ssh named in
// EnvUnlock, clearing the variable; ok is false when there is none.
func CredentialsFromEnv() (creds nbtunnel.Credentials, ok bool, err error) {
	path := os.Getenv(EnvUnlock)
	if path == "" {
		return creds, false, nil
	}
	if err := os.Unsetenv(EnvUnlock); err != nil {
		return creds, false, fmt.Errorf("clear %s: %w", EnvUnlock, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return creds, false, fmt.Errorf("read %s: %w", EnvUnlock, err)
	}
	RemoveStash(path)
	if err := json.Unmarshal(data, &creds); err != nil {
		return creds, false, fmt.Errorf("parse %s: %w", EnvUnlock, err)
	}
	if creds.SetupKey == "" || creds.ManagementURL == "" {
		return creds, false, fmt.Errorf("%s carries no credentials", EnvUnlock)
	}
	return creds, true, nil
}

// newNodeClient builds the node service client; tests point it at a fake.
var newNodeClient = func(store externalnode.TokenProvider) nodev1connect.ExternalNodeServiceClient {
	return register.NewNodeServiceClient(store, config.GlobalConfig.GetBrevPublicAPIURL())
}

// Credentials fetches the setup key Brev currently issues for the node this
// device registered as, which is what unlocks the sealed tunnel identity. It
// needs a valid Brev session: that is the point, a device whose Brev login
// expired cannot start the tunnel from the identity on disk alone.
func Credentials(ctx context.Context, store externalnode.TokenProvider, id nbtunnel.Identity) (nbtunnel.Credentials, error) {
	if _, err := store.GetAccessToken(); err != nil {
		return nbtunnel.Credentials{}, fmt.Errorf("%w (%v)", ErrNotLoggedIn, err)
	}
	resp, err := newNodeClient(store).GetNode(ctx, connect.NewRequest(&nodev1.GetNodeRequest{ExternalNodeId: id.NodeID}))
	if err != nil {
		return nbtunnel.Credentials{}, nodeError(id, err)
	}
	command := resp.Msg.GetExternalNode().GetConnectivityInfo().GetRegistrationCommand()
	if command == "" {
		return nbtunnel.Credentials{}, fmt.Errorf("Brev returned no registration command for node %s; the tunnel identity cannot be unlocked", id.NodeID)
	}
	creds, err := nbtunnel.ParseRegistrationCommand(command)
	if err != nil {
		return nbtunnel.Credentials{}, fmt.Errorf("parse registration command: %w", err)
	}
	return creds, nil
}

// Open fetches the unlock credentials for the identity under dir and opens
// the tunnel with them.
func Open(ctx context.Context, store externalnode.TokenProvider, dir string) (*nbtunnel.Tunnel, error) {
	id, err := nbtunnel.ReadIdentity(dir)
	if err != nil {
		return nil, err //nolint:wrapcheck // names the remedy already
	}
	creds, err := Credentials(ctx, store, id)
	if err != nil {
		return nil, err
	}
	return nbtunnel.Open(dir, creds) //nolint:wrapcheck // names the remedy already
}

// nodeError turns the RPC failures a stale or revoked device meets into
// actionable messages; anything else keeps the raw error.
func nodeError(id nbtunnel.Identity, err error) error {
	switch connect.CodeOf(err) {
	case connect.CodeUnauthenticated:
		return fmt.Errorf("%w (%v)", ErrNotLoggedIn, err)
	case connect.CodeNotFound, connect.CodePermissionDenied:
		return fmt.Errorf("Brev no longer returns node %s (%s) for this login, so the tunnel identity cannot be unlocked; run 'brev deregister' and then 'brev register --embedded' again: %w", id.NodeID, id.DeviceName, err)
	default:
		return fmt.Errorf("fetch node %s: %w", id.NodeID, err)
	}
}
