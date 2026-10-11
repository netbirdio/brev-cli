package tunnel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	nodev1connect "buf.build/gen/go/brevdev/devplane/connectrpc/go/devplaneapi/v1/devplaneapiv1connect"
	nodev1 "buf.build/gen/go/brevdev/devplane/protocolbuffers/go/devplaneapi/v1"
	"connectrpc.com/connect"

	"github.com/brevdev/brev-cli/pkg/externalnode"
	"github.com/brevdev/brev-cli/pkg/nbtunnel"
)

type tokenStub struct{ err error }

func (s tokenStub) GetAccessToken() (string, error) { return "token", s.err }

type fakeNodes struct {
	nodev1connect.UnimplementedExternalNodeServiceHandler
	getNode func(*nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error)
}

func (f *fakeNodes) GetNode(_ context.Context, req *connect.Request[nodev1.GetNodeRequest]) (*connect.Response[nodev1.GetNodeResponse], error) {
	resp, err := f.getNode(req.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// useFakeNodes serves svc over an httptest server and points Credentials at it.
func useFakeNodes(t *testing.T, svc *fakeNodes) {
	t.Helper()
	_, handler := nodev1connect.NewExternalNodeServiceHandler(svc)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	prev := newNodeClient
	newNodeClient = func(externalnode.TokenProvider) nodev1connect.ExternalNodeServiceClient {
		return nodev1connect.NewExternalNodeServiceClient(http.DefaultClient, server.URL)
	}
	t.Cleanup(func() { newNodeClient = prev })
}

var testIdentity = nbtunnel.Identity{NodeID: "unode_abc", DeviceName: "laptop", ManagementURL: "https://m.example.com"}

func TestCredentialsNeedsASession(t *testing.T) {
	useFakeNodes(t, &fakeNodes{getNode: func(*nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
		t.Fatal("GetNode must not be called without a Brev session")
		return nil, nil
	}})
	_, err := Credentials(context.Background(), tokenStub{err: errors.New("no tokens")}, testIdentity)
	if !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("Credentials without a session: got %v, want ErrNotLoggedIn", err)
	}
}

func TestCredentialsParsesTheNodesCommand(t *testing.T) {
	var asked string
	useFakeNodes(t, &fakeNodes{getNode: func(req *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
		asked = req.GetExternalNodeId()
		return &nodev1.GetNodeResponse{ExternalNode: &nodev1.ExternalNode{
			ExternalNodeId:   req.GetExternalNodeId(),
			ConnectivityInfo: &nodev1.ConnectivityInfo{RegistrationCommand: "netbird up --setup-key 7F3A2C19-5B6E-4D80-9A1C-2E4F6B8D0C13 --management-url https://m.example.com"},
		}}, nil
	}})
	creds, err := Credentials(context.Background(), tokenStub{}, testIdentity)
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if asked != "unode_abc" {
		t.Errorf("GetNode asked for %q, want the identity's node", asked)
	}
	if creds.SetupKey != "7F3A2C19-5B6E-4D80-9A1C-2E4F6B8D0C13" || creds.ManagementURL != "https://m.example.com" {
		t.Errorf("credentials = %+v", creds)
	}
}

func TestCredentialsNamesTheRemedyForAGoneNode(t *testing.T) {
	for _, code := range []connect.Code{connect.CodeNotFound, connect.CodePermissionDenied} {
		useFakeNodes(t, &fakeNodes{getNode: func(*nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
			return nil, connect.NewError(code, errors.New("gone"))
		}})
		_, err := Credentials(context.Background(), tokenStub{}, testIdentity)
		if err == nil || !strings.Contains(err.Error(), "brev deregister") {
			t.Errorf("%s: error should point at deregister, got %v", code, err)
		}
	}
	useFakeNodes(t, &fakeNodes{getNode: func(*nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("expired"))
	}})
	if _, err := Credentials(context.Background(), tokenStub{}, testIdentity); !errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("an unauthenticated GetNode should read as not logged in, got %v", err)
	}
}

func TestCredentialsRejectsAnEmptyCommand(t *testing.T) {
	useFakeNodes(t, &fakeNodes{getNode: func(req *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
		return &nodev1.GetNodeResponse{ExternalNode: &nodev1.ExternalNode{ExternalNodeId: req.GetExternalNodeId()}}, nil
	}})
	if _, err := Credentials(context.Background(), tokenStub{}, testIdentity); err == nil || !strings.Contains(err.Error(), "no registration command") {
		t.Fatalf("expected a no-command error, got %v", err)
	}
}
