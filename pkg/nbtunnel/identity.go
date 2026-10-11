package nbtunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

const (
	identityVersion = 1
	saltSize        = 32
	unlockKeySize   = 32
	unlockKeyInfo   = "brev-cli embedded tunnel identity v1"
)

var (
	// ErrIdentityOutdated means the identity on disk predates sealed
	// identities, or is not one this build can read; re-enrolling replaces it.
	ErrIdentityOutdated = errors.New("the embedded tunnel identity on this device is in an outdated format; run 'brev register --embedded' again to re-enroll")
	// ErrUnlockFailed means the setup key Brev currently issues for the node
	// does not unlock the sealed identity, so it was sealed under another key.
	ErrUnlockFailed = errors.New("the sealed tunnel identity could not be unlocked with the key Brev currently issues for this device; run 'brev deregister' and then 'brev register --embedded' again")
)

// Identity is what brev register persists: the node and control plane the
// device enrolled with, in the clear, and the peer's keys sealed under a key
// derived from the setup key Brev issues for that node. Only an authenticated
// GetNode returns that setup key, so the file alone yields no usable peer, a
// Brev login is needed to start the tunnel, and RemoveNode makes the sealed
// keys unrecoverable.
type Identity struct {
	Version       int    `json:"version"`
	NodeID        string `json:"external_node_id"`
	DeviceName    string `json:"device_name"`
	ManagementURL string `json:"management_url"`
	RegisteredAt  string `json:"registered_at"`
	Sealed        Sealed `json:"sealed"`
}

// Sealed is the encrypted part of an Identity: AES-256-GCM over the peer's
// keys, with the clear fields of the identity as associated data.
type Sealed struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// secrets is what the seal protects: the WireGuard private key management
// knows the peer by, and the SSH host key the embedded client generated.
type secrets struct {
	PrivateKey string `json:"private_key"`
	SSHKey     string `json:"ssh_key,omitempty"`
}

// identityHeader is the clear part of the identity the seal is bound to, so a
// file whose node, name or management URL was edited no longer unlocks.
type identityHeader struct {
	Version       int    `json:"version"`
	NodeID        string `json:"external_node_id"`
	DeviceName    string `json:"device_name"`
	ManagementURL string `json:"management_url"`
}

// ReadIdentity loads the identity under dir without unlocking it. It reports
// ErrNotRegistered when there is none and ErrIdentityOutdated when the file is
// not a sealed identity this build understands.
func ReadIdentity(dir string) (Identity, error) {
	var id Identity
	data, err := os.ReadFile(filepath.Join(dir, identityFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return id, ErrNotRegistered
		}
		return id, fmt.Errorf("read tunnel identity: %w", err)
	}
	if err := json.Unmarshal(data, &id); err != nil {
		return id, fmt.Errorf("parse tunnel identity: %w", err)
	}
	if id.Version != identityVersion || id.NodeID == "" || id.ManagementURL == "" || len(id.Sealed.Ciphertext) == 0 {
		return id, ErrIdentityOutdated
	}
	return id, nil
}

// IsRegistered reports whether dir holds a sealed identity.
func IsRegistered(dir string) bool {
	_, err := ReadIdentity(dir)
	return err == nil
}

// CheckUnlock reports whether creds unlock the identity under dir, without
// starting anything, so a caller can fail before it hands the session to ssh.
func CheckUnlock(dir string, creds Credentials) error {
	id, err := ReadIdentity(dir)
	if err != nil {
		return err
	}
	_, err = id.unseal(creds)
	return err
}

// seal encrypts s into id under the key creds derives, with a fresh salt and
// nonce, and stamps the format version.
func (id *Identity) seal(s secrets, creds Credentials) error {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	id.Version = identityVersion
	aead, err := id.aead(creds, salt)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	plain, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode tunnel secrets: %w", err)
	}
	aad, err := id.header()
	if err != nil {
		return err
	}
	id.Sealed = Sealed{Salt: salt, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plain, aad)}
	return nil
}

// unseal decrypts the sealed keys with the key creds derives. Any mismatch,
// whether a rotated setup key or an edited header, surfaces as ErrUnlockFailed.
func (id Identity) unseal(creds Credentials) (secrets, error) {
	var s secrets
	if id.Version != identityVersion || len(id.Sealed.Ciphertext) == 0 {
		return s, ErrIdentityOutdated
	}
	aead, err := id.aead(creds, id.Sealed.Salt)
	if err != nil {
		return s, err
	}
	if len(id.Sealed.Nonce) != aead.NonceSize() {
		return s, ErrUnlockFailed
	}
	aad, err := id.header()
	if err != nil {
		return s, err
	}
	plain, err := aead.Open(nil, id.Sealed.Nonce, id.Sealed.Ciphertext, aad)
	if err != nil {
		return s, ErrUnlockFailed
	}
	if err := json.Unmarshal(plain, &s); err != nil || s.PrivateKey == "" {
		return secrets{}, ErrUnlockFailed
	}
	return s, nil
}

func (id Identity) aead(creds Credentials, salt []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, setupKeyMaterial(creds.SetupKey), salt, unlockKeyInfo+"\x00"+id.NodeID, unlockKeySize)
	if err != nil {
		return nil, fmt.Errorf("derive unlock key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init cipher: %w", err)
	}
	return aead, nil
}

func (id Identity) header() ([]byte, error) {
	data, err := json.Marshal(identityHeader{
		Version:       id.Version,
		NodeID:        id.NodeID,
		DeviceName:    id.DeviceName,
		ManagementURL: id.ManagementURL,
	})
	if err != nil {
		return nil, fmt.Errorf("encode identity header: %w", err)
	}
	return data, nil
}

// setupKeyMaterial canonicalizes the setup key before it is used as key
// material: management requires a UUID, and Brev may print it in either case.
func setupKeyMaterial(setupKey string) []byte {
	trimmed := strings.TrimSpace(setupKey)
	if u, err := uuid.Parse(trimmed); err == nil {
		return u[:]
	}
	return []byte(strings.ToUpper(trimmed))
}

// clearIdentity removes the identity and the plaintext config an earlier
// build of brev left behind, so an enrollment starts from nothing on disk.
func clearIdentity(dir string) error {
	for _, name := range []string{identityFile, legacyConfigFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale %s: %w", name, err)
		}
	}
	return nil
}
