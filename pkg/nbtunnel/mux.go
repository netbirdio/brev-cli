package nbtunnel

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	// ControlPath keeps --netbird sessions on their own ssh control socket, so
	// a gateway session to the same alias never multiplexes over the overlay.
	ControlPath = "~/.brev/nb-control-%C"
	// ControlPersist keeps the master, and with it nb-proxy and the engine, up
	// after the last session ends, so a reconnect within it skips the start.
	ControlPersist = "10m"
	// releaseWait bounds the wait for a stopped master's nb-proxy to let go of
	// the identity lock: its Close stops the engine first, up to stopTimeout.
	releaseWait = stopTimeout + 2*time.Second
)

// MasterAlive asks OpenSSH whether a --netbird control master for alias is up.
func MasterAlive(alias string) bool {
	cmd := exec.Command("ssh", "-o", "ControlPath="+ControlPath, "-O", "check", alias) //nolint:gosec // alias is a brev ssh alias
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Run() == nil
}

// MasterStop asks the control master for alias to exit once its sessions are
// done: an idle master exits at once, one still carrying a session keeps it.
func MasterStop(alias string) error {
	cmd := exec.Command("ssh", "-o", "ControlPath="+ControlPath, "-O", "stop", alias) //nolint:gosec // alias is a brev ssh alias
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("stop the ssh control master for %s: %w", alias, err)
	}
	return nil
}

// ReleaseIdleMasters stops the control masters of remembered targets, whose
// nb-proxy holds the identity lock for as long as they live, then waits for
// the lock to come free. It returns the aliases it stopped; a master still
// carrying a session keeps the lock, and the error names it.
func ReleaseIdleMasters(ctx context.Context, dir string) ([]string, error) {
	targets, err := ReadTargets(dir)
	if err != nil {
		return nil, err
	}
	var stopped []string
	for _, t := range targets {
		if !MasterAlive(t.Alias) {
			continue
		}
		if err := MasterStop(t.Alias); err != nil {
			return stopped, err
		}
		stopped = append(stopped, t.Alias)
	}
	if len(stopped) == 0 {
		return nil, nil
	}
	deadline := time.Now().Add(releaseWait)
	for {
		err := CheckAvailable(dir)
		if err == nil || !errors.Is(err, ErrLocked) {
			return stopped, err
		}
		if time.Now().After(deadline) {
			return stopped, fmt.Errorf("%w: an open 'brev ssh --netbird' session to %s still holds it", ErrLocked, strings.Join(stopped, ", "))
		}
		select {
		case <-ctx.Done():
			return stopped, fmt.Errorf("wait for the identity lock: %w", ctx.Err())
		case <-time.After(peerPoll):
		}
	}
}
