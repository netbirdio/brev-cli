package nbtunnel

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testSetupKey  = "7F3A2C19-5B6E-4D80-9A1C-2E4F6B8D0C13"
	testPrivate   = "cPrivateKeyBytesThatMustNeverTouchDiskInTheClear="
	testSSHKey    = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
	testNodeID    = "unode_abc"
	testMgmtURL   = "https://m.example.com"
	testDevice    = "laptop"
	testOtherKeys = "11111111-2222-4333-8444-555555555555"
)

func testCreds(setupKey string) Credentials {
	return Credentials{SetupKey: setupKey, ManagementURL: testMgmtURL}
}

func sealedIdentity(t *testing.T) Identity {
	t.Helper()
	id := Identity{NodeID: testNodeID, DeviceName: testDevice, ManagementURL: testMgmtURL, RegisteredAt: "2026-10-11T00:00:00Z"}
	if err := id.seal(secrets{PrivateKey: testPrivate, SSHKey: testSSHKey}, testCreds(testSetupKey)); err != nil {
		t.Fatalf("seal: %v", err)
	}
	return id
}

func writeSealedIdentity(t *testing.T, dir string) {
	t.Helper()
	if err := writeJSON(filepath.Join(dir, identityFile), sealedIdentity(t)); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
}

func TestSealedIdentityKeepsNoSecretInTheClear(t *testing.T) {
	dir := t.TempDir()
	writeSealedIdentity(t, dir)
	raw, err := os.ReadFile(filepath.Join(dir, identityFile))
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}
	for _, secret := range []string{testPrivate, "OPENSSH PRIVATE KEY", testSetupKey} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("identity file must not contain %q in the clear", secret)
		}
	}
	info, err := os.Stat(filepath.Join(dir, identityFile))
	if err != nil {
		t.Fatalf("stat identity: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("identity file mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestSealUnsealRoundTrip(t *testing.T) {
	dir := t.TempDir()
	writeSealedIdentity(t, dir)

	got, err := ReadIdentity(dir)
	if err != nil {
		t.Fatalf("ReadIdentity: %v", err)
	}
	if got.NodeID != testNodeID || got.DeviceName != testDevice || got.ManagementURL != testMgmtURL || got.Version != identityVersion {
		t.Errorf("identity header = %+v", got)
	}
	keys, err := got.unseal(testCreds(testSetupKey))
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if keys.PrivateKey != testPrivate || keys.SSHKey != testSSHKey {
		t.Errorf("unsealed keys = %+v, want the sealed ones", keys)
	}
	if !IsRegistered(dir) {
		t.Error("IsRegistered should be true for a sealed identity")
	}
	if err := CheckUnlock(dir, testCreds(testSetupKey)); err != nil {
		t.Errorf("CheckUnlock with the right key: %v", err)
	}
	if err := Remove(dir); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if IsRegistered(dir) {
		t.Error("IsRegistered should be false after Remove")
	}
}

func TestUnsealRejectsWrongSetupKey(t *testing.T) {
	id := sealedIdentity(t)
	if _, err := id.unseal(testCreds(testOtherKeys)); !errors.Is(err, ErrUnlockFailed) {
		t.Fatalf("unseal with another setup key: got %v, want ErrUnlockFailed", err)
	}
}

func TestUnsealAcceptsRecasedSetupKey(t *testing.T) {
	id := sealedIdentity(t)
	recased := "  " + strings.ToLower(testSetupKey) + "\n"
	if _, err := id.unseal(testCreds(recased)); err != nil {
		t.Fatalf("a lower-case, padded spelling of the same UUID must unlock: %v", err)
	}
}

func TestUnsealRejectsEditedHeader(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Identity)
	}{
		{"management url", func(id *Identity) { id.ManagementURL = "https://evil.example.com" }},
		{"node id", func(id *Identity) { id.NodeID = "unode_other" }},
		{"device name", func(id *Identity) { id.DeviceName = "other" }},
		{"ciphertext", func(id *Identity) { id.Sealed.Ciphertext[0] ^= 0xff }},
		{"nonce length", func(id *Identity) { id.Sealed.Nonce = id.Sealed.Nonce[:4] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := sealedIdentity(t)
			tc.edit(&id)
			if _, err := id.unseal(testCreds(testSetupKey)); !errors.Is(err, ErrUnlockFailed) {
				t.Fatalf("unseal after editing the %s: got %v, want ErrUnlockFailed", tc.name, err)
			}
		})
	}
}

func TestSealUsesFreshSaltAndNonce(t *testing.T) {
	a, b := sealedIdentity(t), sealedIdentity(t)
	if string(a.Sealed.Salt) == string(b.Sealed.Salt) || string(a.Sealed.Nonce) == string(b.Sealed.Nonce) {
		t.Error("two seals of the same secrets must not share salt or nonce")
	}
	if string(a.Sealed.Ciphertext) == string(b.Sealed.Ciphertext) {
		t.Error("two seals of the same secrets must not produce the same ciphertext")
	}
}

func TestReadIdentityRejectsLegacyLayout(t *testing.T) {
	dir := t.TempDir()
	// What builds before sealed identities wrote: a bare header next to the
	// embedded client's own config with the private key in the clear.
	legacy := `{"device_name":"laptop","management_url":"https://m.example.com","registered_at":"2026-10-10T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, identityFile), []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy identity: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, legacyConfigFile), []byte(`{"PrivateKey":"abc="}`), 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}
	if _, err := ReadIdentity(dir); !errors.Is(err, ErrIdentityOutdated) {
		t.Fatalf("ReadIdentity on the legacy layout: got %v, want ErrIdentityOutdated", err)
	}
	if IsRegistered(dir) {
		t.Error("a legacy layout must not count as registered")
	}
	if _, err := Open(dir, testCreds(testSetupKey)); !errors.Is(err, ErrIdentityOutdated) {
		t.Fatalf("Open on the legacy layout: got %v, want ErrIdentityOutdated", err)
	}

	if err := clearIdentity(dir); err != nil {
		t.Fatalf("clearIdentity: %v", err)
	}
	for _, name := range []string{identityFile, legacyConfigFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s should be gone after clearIdentity", name)
		}
	}
}

func TestOpenWithoutIdentity(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, testCreds(testSetupKey)); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("Open on an empty dir: got %v, want ErrNotRegistered", err)
	}
	if IsRegistered(dir) {
		t.Error("IsRegistered should be false for an empty dir")
	}
	if err := CheckUnlock(dir, testCreds(testSetupKey)); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("CheckUnlock on an empty dir: got %v, want ErrNotRegistered", err)
	}
}

func TestOpenWithWrongKeyLeavesNoSession(t *testing.T) {
	dir := t.TempDir()
	writeSealedIdentity(t, dir)
	before := os.Stderr
	if _, err := Open(dir, testCreds(testOtherKeys)); !errors.Is(err, ErrUnlockFailed) {
		t.Fatalf("Open with another setup key: got %v, want ErrUnlockFailed", err)
	}
	if os.Stderr != before {
		t.Error("a refused unlock must not leave stderr redirected")
	}
	if err := CheckAvailable(dir); err != nil {
		t.Errorf("a refused unlock must not hold the identity lock: %v", err)
	}
}
