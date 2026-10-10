package register

import (
	"context"
	"errors"
	"strings"
	"testing"

	nodev1 "buf.build/gen/go/brevdev/devplane/protocolbuffers/go/devplaneapi/v1"

	"github.com/brevdev/brev-cli/pkg/terminal"
)

type mockEmbeddedTunnel struct {
	registered bool
	name       string
	command    string
	err        error
	calls      int
}

func (m *mockEmbeddedTunnel) Register(_ context.Context, deviceName, registrationCommand string) error {
	m.calls++
	m.name, m.command = deviceName, registrationCommand
	if m.err != nil {
		return m.err
	}
	m.registered = true
	return nil
}

func (m *mockEmbeddedTunnel) IsRegistered() bool { return m.registered }

// refusingGater fails the test if the sudo gate is consulted at all.
type refusingGater struct{}

func (refusingGater) Gate(*terminal.Terminal, terminal.Confirmer, string, bool) error {
	return errors.New("sudo must not be requested for an embedded registration")
}

func embeddedOpts() registerOpts {
	return registerOpts{interactive: false, name: "my-laptop", orgName: "TestOrg", embedded: true}
}

func Test_runRegister_Embedded(t *testing.T) {
	userStore := &mockRegistrationStore{}
	svc := &fakeNodeService{addNodeFn: okAddNodeFn(nil)}
	deps, server := testRegisterDeps(t, svc, &mockRegistrationStore{})
	defer server.Close()

	tunnel := &mockEmbeddedTunnel{}
	setupRunner := &mockSetupRunner{}
	deps.userRegistrationStore = userStore
	deps.tunnel = tunnel
	deps.setupRunner = setupRunner
	// Embedded mode must need neither Linux, nor sudo, nor a native install.
	deps.platform = mockPlatform{compatible: false}
	deps.gater = refusingGater{}
	deps.netbird = mockNetBirdManager{err: errors.New("install must not run")}

	err := runRegister(context.Background(), terminal.New(), testRegisterStore(), embeddedOpts(), deps)
	if err != nil {
		t.Fatalf("runRegister: %v", err)
	}
	if tunnel.calls != 1 || tunnel.name != "my-laptop" || tunnel.command != "netbird up --key abc" {
		t.Errorf("tunnel registration = %+v, want one call for my-laptop with the AddNode command", tunnel)
	}
	if setupRunner.called {
		t.Error("the native setup command must not run in embedded mode")
	}
	reg, err := userStore.Load()
	if err != nil {
		t.Fatalf("user store Load: %v", err)
	}
	if !reg.Embedded || reg.ExternalNodeID != "unode_abc" || reg.Status != RegistrationStatusRegistered {
		t.Errorf("persisted registration = %+v, want an embedded registered record", reg)
	}
}

func Test_runRegister_Embedded_TunnelFailureKeepsRecord(t *testing.T) {
	userStore := &mockRegistrationStore{}
	svc := &fakeNodeService{addNodeFn: okAddNodeFn(nil)}
	deps, server := testRegisterDeps(t, svc, &mockRegistrationStore{})
	defer server.Close()
	deps.userRegistrationStore = userStore
	deps.tunnel = &mockEmbeddedTunnel{err: errors.New("management unreachable")}

	err := runRegister(context.Background(), terminal.New(), testRegisterStore(), embeddedOpts(), deps)
	if err == nil || !strings.Contains(err.Error(), "management unreachable") {
		t.Fatalf("expected the tunnel failure to surface, got %v", err)
	}
	// The node exists on Brev, so the record stays and a re-run re-enrolls.
	reg, err := userStore.Load()
	if err != nil {
		t.Fatalf("user store Load: %v", err)
	}
	if !reg.Embedded || reg.ExternalNodeID != "unode_abc" {
		t.Errorf("persisted registration = %+v, want the registered node kept", reg)
	}
}

func Test_runRegister_Embedded_ReenrollsMissingIdentity(t *testing.T) {
	userStore := &mockRegistrationStore{reg: &DeviceRegistration{
		ExternalNodeID: "unode_abc",
		DisplayName:    "my-laptop",
		OrgID:          "org_123",
		DeviceID:       "dev-laptop",
		Status:         RegistrationStatusRegistered,
		Embedded:       true,
	}}
	svc := &fakeNodeService{getNodeFn: func(req *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
		return &nodev1.GetNodeResponse{ExternalNode: &nodev1.ExternalNode{
			ExternalNodeId:   req.GetExternalNodeId(),
			Name:             "my-laptop",
			ConnectivityInfo: &nodev1.ConnectivityInfo{RegistrationCommand: "netbird up --setup-key fresh --management-url https://m.example.com"},
		}}, nil
	}}
	deps, server := testRegisterDeps(t, svc, &mockRegistrationStore{})
	defer server.Close()
	tunnel := &mockEmbeddedTunnel{}
	deps.userRegistrationStore = userStore
	deps.tunnel = tunnel

	err := runRegister(context.Background(), terminal.New(), testRegisterStore(), embeddedOpts(), deps)
	if err != nil {
		t.Fatalf("runRegister: %v", err)
	}
	if tunnel.calls != 1 || !strings.Contains(tunnel.command, "fresh") {
		t.Errorf("expected one re-enrollment with the node's current command, got %+v", tunnel)
	}
}

func Test_runRegister_Embedded_IdentityPresentIsNoop(t *testing.T) {
	userStore := &mockRegistrationStore{reg: &DeviceRegistration{
		ExternalNodeID: "unode_abc", DisplayName: "my-laptop", OrgID: "org_123", DeviceID: "dev-laptop",
		Status: RegistrationStatusRegistered, Embedded: true,
	}}
	deps, server := testRegisterDeps(t, &fakeNodeService{}, &mockRegistrationStore{})
	defer server.Close()
	tunnel := &mockEmbeddedTunnel{registered: true}
	deps.userRegistrationStore = userStore
	deps.tunnel = tunnel

	if err := runRegister(context.Background(), terminal.New(), testRegisterStore(), embeddedOpts(), deps); err != nil {
		t.Fatalf("runRegister: %v", err)
	}
	if tunnel.calls != 0 {
		t.Errorf("an intact identity must not be re-enrolled, got %d calls", tunnel.calls)
	}
}

func Test_runRegister_Embedded_RefusesNativeRegistration(t *testing.T) {
	deps, server := testRegisterDeps(t, &fakeNodeService{}, &mockRegistrationStore{reg: registeredReg()})
	defer server.Close()
	deps.userRegistrationStore = &mockRegistrationStore{}
	deps.tunnel = &mockEmbeddedTunnel{}

	err := runRegister(context.Background(), terminal.New(), testRegisterStore(), embeddedOpts(), deps)
	if err == nil || !strings.Contains(err.Error(), "native") {
		t.Fatalf("expected a refusal naming the native registration, got %v", err)
	}
}

func Test_runRegister_Native_RefusesEmbeddedRegistration(t *testing.T) {
	deps, server := testRegisterDeps(t, &fakeNodeService{}, &mockRegistrationStore{})
	defer server.Close()
	deps.userRegistrationStore = &mockRegistrationStore{reg: &DeviceRegistration{
		ExternalNodeID: "unode_x", OrgID: "org_123", Status: RegistrationStatusRegistered, Embedded: true,
	}}

	err := runRegister(context.Background(), terminal.New(), testRegisterStore(),
		registerOpts{interactive: false, name: "my-spark", orgName: "TestOrg"}, deps)
	if err == nil || !strings.Contains(err.Error(), "--embedded") {
		t.Fatalf("expected a refusal pointing at --embedded, got %v", err)
	}
}

func Test_nodeLabels(t *testing.T) {
	if got := nodeLabels(false); got["tunnel"] != "" || got["sshprovider"] != "certauth" {
		t.Errorf("native labels = %v", got)
	}
	if got := nodeLabels(true); got["tunnel"] != "embedded" || got["sshprovider"] != "certauth" {
		t.Errorf("embedded labels = %v", got)
	}
}
