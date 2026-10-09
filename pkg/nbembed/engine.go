//go:build linux || darwin

package nbembed

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/netbirdio/netbird/client/embed"
)

func newEmbeddedEngine(dir string, p profileInfo, setupKey string) (engine, error) {
	// This function runs only in the isolated helper process. Avoid optional
	// host/router integration even when inherited NetBird defaults change.
	for _, name := range []string{"NB_DISABLE_NAT_MAPPER", "NB_WG_KERNEL_DISABLED"} {
		if err := os.Setenv(name, "true"); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"netbird.json", "state.json"} {
		path := filepath.Join(dir, name)
		if _, err := os.Lstat(path); err == nil {
			if _, err := readPrivateFile(path, 4<<20); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	port := 0
	opts := embed.Options{
		DeviceName: p.DeviceName, ManagementURL: p.ManagementURL,
		ConfigPath: filepath.Join(dir, "netbird.json"), StatePath: filepath.Join(dir, "state.json"),
		BlockInbound: true, DisableClientRoutes: true, BlockLANAccess: true,
		WireguardPort: &port, LogOutput: io.Discard, LogLevel: "error",
	}
	if setupKey != "" {
		opts.SetupKey = setupKey
	} else {
		data, err := readPrivateFile(opts.ConfigPath, 1<<20)
		if err != nil {
			return nil, errors.New("device identity is unavailable; enroll this device again")
		}
		var identity struct{ PrivateKey string }
		if err := json.Unmarshal(data, &identity); err != nil || identity.PrivateKey == "" {
			return nil, errors.New("device identity is invalid")
		}
		opts.PrivateKey = identity.PrivateKey
	}
	c, err := embed.New(opts)
	if err != nil {
		return nil, errors.New("could not initialize the embedded NetBird client")
	}
	if err := os.Chmod(opts.ConfigPath, 0600); err != nil {
		return nil, err
	}
	cfg, err := c.GetConfig()
	if err != nil {
		return nil, errors.New("could not inspect embedded NetBird configuration")
	}
	expected, _ := url.Parse(p.ManagementURL)
	if cfg.ManagementURL == nil || normalizedURL(cfg.ManagementURL) != normalizedURL(expected) {
		return nil, errors.New("system NetBird policy overrides this device's management URL")
	}
	if !cfg.BlockInbound || !cfg.BlockLANAccess || !cfg.DisableClientRoutes || !cfg.DisableServerRoutes || (cfg.ServerSSHAllowed != nil && *cfg.ServerSSHAllowed) || (cfg.RemoteJobsAllowed != nil && *cfg.RemoteJobsAllowed) {
		return nil, errors.New("system NetBird policy conflicts with client-only access")
	}
	return &embeddedEngine{Client: c}, nil
}

type embeddedEngine struct{ *embed.Client }

func (e *embeddedEngine) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	addr, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, errors.New("invalid direct SSH target address")
	}
	// Start precedes the first map. Wait for this target in the active peer
	// roster instead of running Status(), which performs blocking probes.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, _, ok := e.IdentityForIP(addr.Addr()); ok {
			return e.Client.Dial(ctx, network, address)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func normalizedURL(u *url.URL) string {
	copyURL := *u
	if copyURL.Port() == "443" {
		copyURL.Host = copyURL.Hostname()
	}
	return copyURL.String()
}
