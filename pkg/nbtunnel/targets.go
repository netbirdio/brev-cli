package nbtunnel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"
)

const (
	targetsFile = "targets.json"
	// ReuseWindow bounds how long a remembered target is reused without asking
	// Brev again, so an access revoked meanwhile is noticed within it even
	// while reconnects keep refreshing the control master.
	ReuseWindow = 10 * time.Minute
)

// Target is what a cold 'brev ssh --netbird' resolved through the Brev API
// for one ssh alias, remembered so a reconnect over a live control master
// needs no lookup. Nothing in it is secret.
type Target struct {
	Name      string     `json:"name"`
	ID        string     `json:"id,omitempty"`
	Alias     string     `json:"alias"`
	Addr      netip.Addr `json:"addr"`
	Port      uint16     `json:"port"`
	Host      bool       `json:"host"`
	Workspace bool       `json:"workspace"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// LiveTarget returns the remembered target for one of the spellings a user
// typed (name, id, alias) whose control master alive reports up, and which
// was resolved within ReuseWindow. When several match, an id match wins,
// then an instance over a machine, then the alias order, so the choice is
// the one the cold path would make.
func LiveTarget(dir string, spellings []string, alive func(alias string) bool) (Target, bool) {
	targets, err := ReadTargets(dir)
	if err != nil {
		return Target{}, false
	}
	var candidates []Target
	for _, t := range targets {
		if t.matches(spellings) && time.Since(t.UpdatedAt) <= ReuseWindow {
			candidates = append(candidates, t)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		ri, rj := candidates[i].rank(spellings), candidates[j].rank(spellings)
		if ri != rj {
			return ri < rj
		}
		return candidates[i].Alias < candidates[j].Alias
	})
	for _, t := range candidates {
		if alive(t.Alias) {
			return t, true
		}
	}
	return Target{}, false
}

func (t Target) matches(spellings []string) bool {
	return slices.Contains(spellings, t.Name) || slices.Contains(spellings, t.Alias) || (t.ID != "" && slices.Contains(spellings, t.ID))
}

func (t Target) rank(spellings []string) int {
	switch {
	case t.ID != "" && slices.Contains(spellings, t.ID):
		return 0
	case t.Workspace:
		return 1
	default:
		return 2
	}
}

// RememberTarget records t for LiveTarget, stamped with the current time.
func RememberTarget(dir string, t Target) error {
	targets, err := ReadTargets(dir)
	if err != nil {
		return err
	}
	t.UpdatedAt = time.Now().UTC()
	targets[t.Alias] = t
	return writeTargets(dir, targets)
}

// ForgetTarget drops the entry for alias, if any.
func ForgetTarget(dir, alias string) error {
	targets, err := ReadTargets(dir)
	if err != nil {
		return err
	}
	if _, ok := targets[alias]; !ok {
		return nil
	}
	delete(targets, alias)
	return writeTargets(dir, targets)
}

// ReadTargets loads the remembered targets by alias. A damaged file only
// costs a lookup, so it reads as empty rather than failing.
func ReadTargets(dir string) (map[string]Target, error) {
	targets := map[string]Target{}
	data, err := os.ReadFile(filepath.Join(dir, targetsFile))
	if errors.Is(err, os.ErrNotExist) {
		return targets, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", targetsFile, err)
	}
	if err := json.Unmarshal(data, &targets); err != nil {
		return map[string]Target{}, nil
	}
	return targets, nil
}

func writeTargets(dir string, targets map[string]Target) error {
	data, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", targetsFile, err)
	}
	if err := os.WriteFile(filepath.Join(dir, targetsFile), data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", targetsFile, err)
	}
	return nil
}
