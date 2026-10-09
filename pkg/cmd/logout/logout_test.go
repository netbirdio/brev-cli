package logout

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeLogoutAuth struct {
	events *[]string
	err    error
}

func (a fakeLogoutAuth) Logout() error {
	*a.events = append(*a.events, "auth")
	return a.err
}

type fakeLogoutStore struct {
	events    *[]string
	workspace string
}

func (s fakeLogoutStore) GetCurrentWorkspaceID() (string, error) { return s.workspace, nil }
func (s fakeLogoutStore) ClearDefaultOrganization() error {
	*s.events = append(*s.events, "organization")
	return nil
}

func TestLogoutCleansLocalTransportBeforeCredentialsAndPreservesErrors(t *testing.T) {
	var events []string
	opts := LogoutOptions{
		auth:  fakeLogoutAuth{events: &events, err: errors.New("auth cleanup failed")},
		store: fakeLogoutStore{events: &events},
		cleanupLocal: func() error {
			events = append(events, "transport")
			return errors.New("transport cleanup failed")
		},
	}
	err := opts.RunLogout()
	if err == nil {
		t.Fatal("expected cleanup failures")
	}
	if want := []string{"transport", "auth", "organization"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("cleanup order = %v, want %v", events, want)
	}
	for _, failure := range []string{"auth cleanup failed", "transport cleanup failed"} {
		if !strings.Contains(err.Error(), failure) {
			t.Fatalf("missing %q in %v", failure, err)
		}
	}
}

func TestWorkspaceLogoutDoesNotRemoveLocalTransport(t *testing.T) {
	var events []string
	opts := LogoutOptions{
		auth:         fakeLogoutAuth{events: &events},
		store:        fakeLogoutStore{events: &events, workspace: "workspace"},
		cleanupLocal: func() error { t.Fatal("cleanup called inside workspace"); return nil },
	}
	if err := opts.RunLogout(); err == nil {
		t.Fatal("expected workspace logout to be refused")
	}
	if len(events) != 0 {
		t.Fatalf("unexpected cleanup: %v", events)
	}
}
