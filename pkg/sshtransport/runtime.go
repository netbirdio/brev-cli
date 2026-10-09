package sshtransport

import (
	"os"
	"path/filepath"
)

// IsConfigured reports whether an alias uses the explicit pilot profile. Such
// sessions must not be retried after an SSH command has already run.
func IsConfigured(alias string) bool {
	configured, _ := configuredMode(defaultDirectory(), alias)
	return configured
}

// ConnectTimeout leaves legacy connections unchanged and gives an explicitly
// configured direct connection time to start its user-level helper.
func ConnectTimeout(alias string, legacySeconds int) int {
	configured, mode := configuredMode(defaultDirectory(), alias)
	if configured && mode == Direct {
		return 60
	}
	return legacySeconds
}

func defaultDirectory() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".brev", "netbird")
}

func configuredMode(dir, alias string) (bool, string) {
	if dir == "" {
		return false, ""
	}
	mode, err := Mode(dir)
	if err != nil {
		return false, ""
	}
	targets, err := LoadTargets(dir)
	if err != nil {
		return false, ""
	}
	for _, target := range targets {
		if target.Alias == alias {
			return true, mode
		}
	}
	return false, ""
}
