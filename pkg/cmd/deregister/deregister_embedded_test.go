package deregister

import (
	"errors"
	"testing"

	nodev1 "buf.build/gen/go/brevdev/devplane/protocolbuffers/go/devplaneapi/v1"

	"github.com/brevdev/brev-cli/pkg/cmd/register"
	"github.com/brevdev/brev-cli/pkg/terminal"
)

// refusingGater fails the test if the sudo gate is consulted at all.
type refusingGater struct{}

func (refusingGater) Gate(*terminal.Terminal, terminal.Confirmer, string, bool) error {
	return errors.New("sudo must not be requested for an embedded registration")
}

func embeddedReg() *register.DeviceRegistration {
	return &register.DeviceRegistration{
		ExternalNodeID: "unode_laptop",
		DisplayName:    "my-laptop",
		OrgID:          "org_123",
		DeviceID:       "dev-laptop",
		Status:         register.RegistrationStatusRegistered,
		Embedded:       true,
	}
}

func Test_runDeregister_Embedded(t *testing.T) {
	var removedNode string
	svc := &fakeNodeService{removeNodeFn: func(req *nodev1.RemoveNodeRequest) (*nodev1.RemoveNodeResponse, error) {
		removedNode = req.GetExternalNodeId()
		return &nodev1.RemoveNodeResponse{}, nil
	}}
	userStore := &mockRegistrationStore{reg: embeddedReg()}
	nativeStore := &mockRegistrationStore{}
	netbird := &mockNetBirdManager{}
	tunnelRemoved := false

	err := runDeregisterCase(t, nativeStore, svc, func(d *deregisterDeps) {
		d.userRegistrationStore = userStore
		d.tunnelRemover = func() error { tunnelRemoved = true; return nil }
		d.netbird = netbird
		// An embedded registration needs neither Linux nor sudo.
		d.platform = mockPlatform{compatible: false}
		d.gater = refusingGater{}
	})
	if err != nil {
		t.Fatalf("runDeregister: %v", err)
	}
	if removedNode != "unode_laptop" {
		t.Errorf("RemoveNode called for %q, want unode_laptop", removedNode)
	}
	if !tunnelRemoved {
		t.Error("the embedded tunnel identity was not removed")
	}
	if netbird.called {
		t.Error("the native tunnel must not be uninstalled for an embedded registration")
	}
	if exists, _ := userStore.Exists(); exists {
		t.Error("the embedded registration record should be deleted")
	}
}

func Test_runDeregister_Embedded_UserCancels(t *testing.T) {
	var removeCalled bool
	svc := &fakeNodeService{removeNodeFn: func(*nodev1.RemoveNodeRequest) (*nodev1.RemoveNodeResponse, error) {
		removeCalled = true
		return &nodev1.RemoveNodeResponse{}, nil
	}}
	userStore := &mockRegistrationStore{reg: embeddedReg()}

	err := runDeregisterCase(t, &mockRegistrationStore{}, svc, func(d *deregisterDeps) {
		d.userRegistrationStore = userStore
		d.tunnelRemover = func() error { t.Error("tunnel must not be removed after cancel"); return nil }
		d.prompter = mockSelector{fn: func(_ string, items []string) string { return items[len(items)-1] }}
	})
	if err != nil {
		t.Fatalf("runDeregister: %v", err)
	}
	if removeCalled {
		t.Error("RemoveNode must not run after the user cancels")
	}
	if exists, _ := userStore.Exists(); !exists {
		t.Error("the registration record must survive a cancel")
	}
}
