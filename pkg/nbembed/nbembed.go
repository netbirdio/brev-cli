// Package nbembed owns the experimental, user-scoped NetBird SSH transport.
package nbembed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const startupTimeout = 45 * time.Second
const helperStartupTimeout = 35 * time.Second
const requestTimeout = 15 * time.Second
const shutdownTimeout = 5 * time.Second
const idleTimeout = 30 * time.Minute

// StatusInfo describes local enrollment and helper state, not remote revocation.
type StatusInfo struct {
	Enrolled      bool   `json:"enrolled"`
	Running       bool   `json:"running"`
	Ready         bool   `json:"ready"`
	DeviceName    string `json:"device_name,omitempty"`
	ManagementURL string `json:"management_url,omitempty"`
}

type profileInfo struct {
	ManagementURL string `json:"management_url"`
	DeviceName    string `json:"device_name"`
}

type enrollmentRequest struct {
	ManagementURL string `json:"management_url"`
	DeviceName    string `json:"device_name"`
	SetupKey      string `json:"setup_key"`
}

type request struct {
	Operation string `json:"operation"`
	TargetID  string `json:"target_id,omitempty"`
}

type response struct {
	OK     bool       `json:"ok"`
	Error  string     `json:"error,omitempty"`
	Status StatusInfo `json:"status,omitempty"`
}

type engine interface {
	Start(context.Context) error
	Dial(context.Context, string, string) (net.Conn, error)
	Stop(context.Context) error
}

type engineFactory func(dir string, profile profileInfo, setupKey string) (engine, error)

type startupState struct {
	done chan struct{}
	err  error // Written before done closes; read only after receiving from done.
}

func (s *startupState) ready() bool {
	select {
	case <-s.done:
		return s.err == nil
	default:
		return false
	}
}

// DefaultDir returns the private state directory for the current OS user.
func DefaultDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".brev", "netbird"), nil
}

func validateProfile(p profileInfo) error {
	u, err := url.Parse(p.ManagementURL)
	if err != nil || len(p.ManagementURL) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("management URL must be an HTTPS URL without credentials, query, or fragment")
	}
	if strings.TrimSpace(p.DeviceName) == "" || len(p.DeviceName) > 128 || strings.ContainsAny(p.DeviceName, "\r\n\x00") {
		return errors.New("device name must contain 1 to 128 characters without control characters")
	}
	return nil
}

func readProfile(dir string) (profileInfo, error) {
	var p profileInfo
	data, err := readPrivateFile(filepath.Join(dir, "profile.json"), 16<<10)
	if err != nil {
		return p, fmt.Errorf("device is not enrolled; run brev tunnel enroll: %w", err)
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, errors.New("invalid local device profile")
	}
	return p, validateProfile(p)
}

func targetAddress(dir, id string) (string, error) {
	if id == "" || len(id) > 256 {
		return "", errors.New("target ID is required")
	}
	data, err := readPrivateFile(filepath.Join(dir, "targets.json"), 4<<20)
	if err != nil {
		return "", errors.New("direct SSH targets are not configured; run brev tunnel configure")
	}
	var manifest struct {
		Version int `json:"version"`
		Targets []struct {
			ID      string `json:"id"`
			Address string `json:"address"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || manifest.Version != 1 {
		return "", errors.New("invalid direct SSH target manifest")
	}
	address := ""
	for _, t := range manifest.Targets {
		if t.ID != id {
			continue
		}
		if address != "" {
			return "", errors.New("target ID is duplicated in the direct SSH manifest")
		}
		ap, err := netip.ParseAddrPort(t.Address)
		if err != nil || ap.Port() == 0 || ap.Addr().IsUnspecified() || ap.Addr().IsMulticast() {
			return "", errors.New("target address must be a literal IP and TCP port")
		}
		address = ap.String()
	}
	if address == "" {
		return "", errors.New("target is not configured for direct SSH; run brev tunnel configure")
	}
	return address, nil
}

func writePrivateJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".nb-write-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(data, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func decodeEnrollment(in io.Reader) (enrollmentRequest, error) {
	var r enrollmentRequest
	data, err := io.ReadAll(io.LimitReader(in, 16<<10+1))
	if err != nil || len(data) > 16<<10 {
		return r, errors.New("invalid enrollment input")
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return r, errors.New("invalid enrollment input")
	}
	if err := validateProfile(profileInfo{ManagementURL: r.ManagementURL, DeviceName: r.DeviceName}); err != nil {
		return r, err
	}
	if strings.TrimSpace(r.SetupKey) == "" {
		return r, errors.New("a setup key is required for enrollment")
	}
	return r, nil
}
