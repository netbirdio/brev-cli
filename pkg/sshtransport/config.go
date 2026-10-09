// Package sshtransport configures the explicitly enrolled, pinned SSH targets
// used by the experimental NetBird transport. It does not grant target access.
package sshtransport

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	Gateway      = "gateway"
	Direct       = "direct"
	manifestName = "targets.json"
	profileName  = "ssh-profile.json"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// Target binds an existing Brev SSH alias to an explicitly approved mesh
// destination and trusted OpenSSH server keys. HostKeys contains public keys in
// authorized_keys format, without options. An ID is local to this pilot profile.
type Target struct {
	ID           string   `json:"id"`
	Alias        string   `json:"alias"`
	Address      string   `json:"address"`
	HostKeyAlias string   `json:"host_key_alias"`
	HostKeys     []string `json:"host_keys"`
}

type manifest struct {
	Version int      `json:"version"`
	Targets []Target `json:"targets"`
}

type profile struct {
	Mode              string `json:"mode"`
	ExecutablePath    string `json:"executable_path"`
	UserSSHConfigPath string `json:"user_ssh_config_path"`
	BrevSSHConfigPath string `json:"brev_ssh_config_path"`
}

// Configure adds or replaces one pinned target. The first target starts in
// gateway mode; later configuration preserves the selected mode. Existing Brev
// certificate hooks continue to supply SSH authentication in both modes.
func Configure(dir, userSSHConfigPath, brevSSHConfigPath, executablePath string, target Target) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for _, path := range []string{userSSHConfigPath, brevSSHConfigPath, executablePath} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00%") {
			return fmt.Errorf("SSH configuration and executable paths must be absolute and contain no newlines or percent signs")
		}
	}
	if strings.ContainsAny(dir, "\r\n\x00%") {
		return fmt.Errorf("NetBird state path contains unsupported characters")
	}
	if target.HostKeyAlias == "" {
		target.HostKeyAlias = target.ID
	}
	if err := validateTarget(target); err != nil {
		return err
	}
	if err := validateBrevAlias(brevSSHConfigPath, target.Alias); err != nil {
		return err
	}
	if err := privateDir(dir); err != nil {
		return err
	}
	state, err := loadProfile(dir)
	if errors.Is(err, os.ErrNotExist) {
		state = profile{Mode: Gateway}
	} else if err != nil {
		return err
	}
	state.ExecutablePath = executablePath
	state.UserSSHConfigPath = userSSHConfigPath
	state.BrevSSHConfigPath = brevSSHConfigPath
	targets, err := LoadTargets(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	replaced := false
	for i, existing := range targets {
		if existing.ID == target.ID {
			targets[i] = target
			replaced = true
		} else if existing.Alias == target.Alias || existing.HostKeyAlias == target.HostKeyAlias {
			return fmt.Errorf("alias or host-key identity already belongs to target %q", existing.ID)
		}
	}
	if !replaced {
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	if err := writeJSON(filepath.Join(dir, manifestName), manifest{Version: 1, Targets: targets}); err != nil {
		return err
	}
	if err := render(dir, state, targets); err != nil {
		return err
	}
	if err := installInclude(userSSHConfigPath, brevSSHConfigPath, filepath.Join(dir, "ssh_config")); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, profileName), state)
}

// Use explicitly selects a transport. There is deliberately no automatic
// fallback. Missing configuration returns an error wrapping os.ErrNotExist.
func Use(dir, mode string) error {
	if mode != Direct && mode != Gateway {
		return fmt.Errorf("transport must be direct or gateway")
	}
	state, err := loadProfile(dir)
	if err != nil {
		return err
	}
	targets, err := LoadTargets(dir)
	if err != nil {
		return err
	}
	// Refresh may have removed an alias or changed its gateway implementation.
	// Never install an override for a target whose certificate hook disappeared.
	for _, target := range targets {
		if err := validateBrevAlias(state.BrevSSHConfigPath, target.Alias); err != nil {
			return err
		}
	}
	state.Mode = mode
	if err := render(dir, state, targets); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, profileName), state)
}

// Mode returns the saved transport preference.
func Mode(dir string) (string, error) {
	state, err := loadProfile(dir)
	return state.Mode, err
}

// LoadTargets reads and validates the allowlist consumed by the tunnel helper.
func LoadTargets(dir string) ([]Target, error) {
	var data manifest
	if err := readJSON(filepath.Join(dir, manifestName), &data); err != nil {
		return nil, err
	}
	if data.Version != 1 {
		return nil, fmt.Errorf("unsupported target manifest version %d", data.Version)
	}
	ids, aliases, hostAliases := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, target := range data.Targets {
		if err := validateTarget(target); err != nil {
			return nil, err
		}
		if ids[target.ID] || aliases[target.Alias] || hostAliases[target.HostKeyAlias] {
			return nil, fmt.Errorf("duplicate target, SSH alias, or host-key identity in manifest")
		}
		ids[target.ID], aliases[target.Alias], hostAliases[target.HostKeyAlias] = true, true, true
	}
	return data.Targets, nil
}

// LoadTarget resolves only a configured target ID, never an arbitrary address.
func LoadTarget(dir, id string) (Target, error) {
	targets, err := LoadTargets(dir)
	if err != nil {
		return Target{}, err
	}
	for _, target := range targets {
		if target.ID == id {
			return target, nil
		}
	}
	return Target{}, fmt.Errorf("target %q is not configured; run brev tunnel configure", id)
}

// ReadHostKeys reads trusted sshd public keys supplied out of band. Network
// key-scanning is intentionally not a trust source for this pilot.
func ReadHostKeys(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, err := publicKey(line)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted host key: %w", err)
		}
		keys = append(keys, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("trusted host-key file contains no public keys")
	}
	return keys, nil
}

func validateTarget(target Target) error {
	for _, value := range []string{target.ID, target.Alias, target.HostKeyAlias} {
		if !identifier.MatchString(value) {
			return fmt.Errorf("target ID, alias and host-key alias must use 1-128 letters, digits, dots, underscores or hyphens, starting with a letter or digit")
		}
	}
	address, err := netip.ParseAddrPort(target.Address)
	if err != nil || address.Port() == 0 || address.Addr().Zone() != "" || !address.Addr().IsGlobalUnicast() {
		return fmt.Errorf("target address must be a literal mesh IP and nonzero TCP port")
	}
	if len(target.HostKeys) == 0 {
		return fmt.Errorf("at least one trusted sshd host key is required")
	}
	for _, value := range target.HostKeys {
		if _, err := publicKey(value); err != nil {
			return fmt.Errorf("invalid trusted host key: %w", err)
		}
	}
	return nil
}

func publicKey(value string) (ssh.PublicKey, error) {
	if strings.ContainsAny(value, "\r\n") {
		return nil, fmt.Errorf("each host key must occupy one line")
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(value))
	if err != nil {
		return nil, err
	}
	if len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("host keys must contain only a public key and optional comment")
	}
	if _, certificate := key.(*ssh.Certificate); certificate {
		return nil, fmt.Errorf("supply an sshd public host key, not an SSH certificate")
	}
	return key, nil
}

// Read only Brev's generated file, never execute Match exec while validating.
func validateBrevAlias(path, alias string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	matched, certificate := false, false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(line, "#") {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "host":
			matched = len(fields) == 2 && fields[1] == alias
		case "match":
			matched = len(fields) >= 3 && strings.EqualFold(fields[1], "host") && fields[2] == alias
			if matched && len(fields) >= 5 && strings.EqualFold(fields[3], "exec") && strings.Contains(line, " mint-cert ") {
				certificate = true
			}
		case "proxycommand", "proxyjump":
			if matched && !strings.EqualFold(fields[1], "none") {
				return fmt.Errorf("alias %q uses a proxy; the NetBird pilot requires a plain TCP gateway alias", alias)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if !certificate {
		return fmt.Errorf("alias %q has no Brev mint-cert hook; run brev refresh and select a certificate-enabled alias", alias)
	}
	return nil
}

func render(dir string, state profile, targets []Target) error {
	if state.Mode != Gateway && state.Mode != Direct {
		return fmt.Errorf("invalid saved SSH transport %q", state.Mode)
	}
	var config, hosts strings.Builder
	config.WriteString("# Managed by brev tunnel. Explicit transport; pinned sshd keys in both modes.\n")
	for _, target := range targets {
		fmt.Fprintf(&config, "Host %s\n", target.Alias)
		if state.Mode == Direct {
			command := shellQuote(state.ExecutablePath) + " nb-proxy --state-dir " + shellQuote(dir) + " " + shellQuote(target.ID)
			fmt.Fprintf(&config, "  ProxyCommand %s\n  ConnectTimeout 60\n", command)
		} else {
			config.WriteString("  ProxyCommand none\n")
		}
		fmt.Fprintf(&config, "  HostKeyAlias %s\n  UserKnownHostsFile %s\n", target.HostKeyAlias, configQuote(filepath.Join(dir, "known_hosts")))
		config.WriteString("  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  VerifyHostKeyDNS no\n  UpdateHostKeys no\n  CheckHostIP no\n  ControlMaster no\n  ControlPath none\n  ControlPersist no\n  PubkeyAcceptedAlgorithms *-cert-v01@openssh.com\n  PasswordAuthentication no\n  KbdInteractiveAuthentication no\n\n")
		for _, value := range target.HostKeys {
			key, err := publicKey(value)
			if err != nil {
				return err
			}
			fmt.Fprintf(&hosts, "%s %s", target.HostKeyAlias, ssh.MarshalAuthorizedKey(key))
		}
	}
	// Include is parsed in the caller's current block; restore a neutral block.
	config.WriteString("Host *\n")
	if err := atomicWrite(filepath.Join(dir, "known_hosts"), []byte(hosts.String())); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, "ssh_config"), []byte(config.String()))
}

func installInclude(userPath, brevPath, overlayPath string) error {
	data, err := os.ReadFile(userPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	line := "Include " + configQuote(overlayPath) + "\n"
	config := strings.ReplaceAll(string(data), line, "")
	// Preserve Brev's exact Include spelling so refresh recognizes it and does
	// not prepend an unpinned include ahead of this profile.
	brevLine := "Include " + configQuote(brevPath) + "\n"
	if !strings.Contains(config, brevLine) {
		config = brevLine + config
	}
	if err := os.MkdirAll(filepath.Dir(userPath), 0700); err != nil {
		return err
	}
	return atomicWrite(userPath, []byte(line+config))
}

func configQuote(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func loadProfile(dir string) (profile, error) {
	var state profile
	err := readJSON(filepath.Join(dir, profileName), &state)
	return state, err
}

func readJSON(path string, value any) error {
	if err := regularFile(path); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'))
}

func privateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("NetBird state directory must be a real directory")
	}
	return os.Chmod(path, 0700)
}

func regularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular configuration file %s", path)
	}
	return nil
}

func atomicWrite(path string, data []byte) error {
	if err := regularFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".brev-ssh-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
