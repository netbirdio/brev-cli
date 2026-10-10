package shell

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestNetbirdOptionsKeepGeneratedConfig runs the real OpenSSH client in
// config-dump mode against an entry shaped like the ones brev refresh writes
// (certificate hook in a Match host block, cloudflared ProxyCommand,
// ControlMaster) and asserts that the --netbird options keep the hook, the
// user and the certificate identity while replacing the transport.
func TestNetbirdOptionsKeepGeneratedConfig(t *testing.T) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh not installed")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "hook-ran")
	cfg := fmt.Sprintf(`Match host myws exec "touch %s; true"
  IdentityFile /tmp/brev-certkey
  User certuser
  ProxyCommand cloudflared access ssh --hostname myws.example
  IdentitiesOnly yes
  ForwardAgent yes
  RequestTTY yes
  ControlMaster auto
  ControlPath ~/.ssh/brev-control-%%C
  ControlPersist 10m
`, marker)
	cfgPath := filepath.Join(dir, "config")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	target := meshTarget{addr: netip.MustParseAddr("100.73.1.2"), port: 2222}
	args := []string{"-G", "-F", cfgPath}
	args = append(args, netbirdSSHOptions("/opt/brev", target)...)
	args = append(args, "-o", "ConnectTimeout=5", "myws")
	out, err := exec.Command(sshBin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -G: %v\n%s", err, out)
	}
	got := parseSSHDump(out)

	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the Match exec hook did not run, so brev mint-cert would be skipped")
	}
	if got["user"] != "certuser" {
		t.Errorf("user = %q, want certuser from the Match block", got["user"])
	}
	if !strings.Contains(got["identityfile"], "/tmp/brev-certkey") {
		t.Errorf("identityfile = %q, want the certificate key from the Match block", got["identityfile"])
	}
	if !strings.Contains(got["proxycommand"], "nb-proxy 100.73.1.2 2222") {
		t.Errorf("proxycommand = %q, want the embedded tunnel hop", got["proxycommand"])
	}
	if got["hostname"] != "myws" {
		t.Errorf("hostname = %q, want the alias left untouched", got["hostname"])
	}
	if got["controlmaster"] != "false" {
		t.Errorf("controlmaster = %q, want false", got["controlmaster"])
	}
	if got["connecttimeout"] != "90" {
		t.Errorf("connecttimeout = %q, want 90 (first -o wins)", got["connecttimeout"])
	}
}

func parseSSHDump(out []byte) map[string]string {
	got := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), " ")
		if !found {
			continue
		}
		if prev, ok := got[key]; ok {
			value = prev + " " + value
		}
		got[key] = value
	}
	return got
}
