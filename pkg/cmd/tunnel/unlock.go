package tunnel

import (
	"context"
	"errors"
	"fmt"

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
