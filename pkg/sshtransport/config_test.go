package sshtransport

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type fixture struct {
	dir, user, brev, binary string
	target                  Target
	signer                  ssh.Signer
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "profile with spaces")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	f := fixture{
		dir: filepath.Join(base, "netbird"), user: filepath.Join(base, "user_config"),
		brev: filepath.Join(base, "brev_config"), binary: filepath.Join(base, "brev"), signer: signer,
		target: Target{ID: "env-test", Alias: "training", Address: "100.73.1.2:22", HostKeys: []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))}},
	}
	f.writeBrev(t, "192.0.2.10", "2201")
	return f
}

func (f fixture) writeBrev(t *testing.T, host, port string) {
	t.Helper()
	// A real OpenSSH parse executes only /bin/true, never Brev authentication.
	config := fmt.Sprintf(`Match host training exec "/bin/true mint-cert --environment test"
  HostName %s
  Port %s
  User ubuntu
  IdentityFile /tmp/brev-test-certificate
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  ControlMaster auto
  ControlPath /tmp/legacy-brev-control
Host training
  IdentityFile /tmp/brev-test-static-key
Host unrelated
  HostName 192.0.2.20
  StrictHostKeyChecking no
`, host, port)
	if err := os.WriteFile(f.brev, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) configure(t *testing.T) {
	t.Helper()
	if err := Configure(f.dir, f.user, f.brev, f.binary, f.target); err != nil {
		t.Fatal(err)
	}
}

func sshConfig(t *testing.T, config, alias string) string {
	t.Helper()
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH is required for the configuration compatibility test")
	}
	output, err := exec.Command(sshPath, "-G", "-F", config, alias).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -G: %v\n%s", err, output)
	}
	return string(output)
}

func TestConfigurePreservesCertificateHookAndPinsBothTransports(t *testing.T) {
	f := newFixture(t)
	f.configure(t)
	for _, mode := range []string{Gateway, Direct, Gateway} {
		if err := Use(f.dir, mode); err != nil {
			t.Fatal(err)
		}
		got := sshConfig(t, f.user, f.target.Alias)
		for _, want := range []string{
			"hostname 192.0.2.10\n", "port 2201\n", "user ubuntu\n",
			"identityfile /tmp/brev-test-certificate\n", "stricthostkeychecking true\n",
			"hostkeyalias env-test\n", "controlmaster false\n", "controlpersist no\n",
			"globalknownhostsfile /dev/null\n", "passwordauthentication no\n", "kbdinteractiveauthentication no\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("mode %s: ssh config missing %q:\n%s", mode, want, got)
			}
		}
		if strings.Contains(got, "controlpath /tmp/legacy-brev-control") {
			t.Fatal("pilot inherited a legacy SSH control socket")
		}
		if mode == Direct && !strings.Contains(got, "nb-proxy --state-dir") {
			t.Fatal("direct transport has no proxy")
		}
		if mode == Gateway && strings.Contains(got, "nb-proxy") {
			t.Fatal("gateway transport retained embedded proxy")
		}
	}
	unrelated := sshConfig(t, f.user, "unrelated")
	if strings.Contains(unrelated, "stricthostkeychecking true\n") || strings.Contains(unrelated, "nb-proxy") {
		t.Fatal("pilot configuration leaked into an unrelated alias")
	}
	for _, name := range []string{manifestName, profileName, "ssh_config", "known_hosts"} {
		info, err := os.Stat(filepath.Join(f.dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("private file %s: %v, %v", name, info, err)
		}
	}
	info, err := os.Stat(f.dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("private directory: %v, %v", info, err)
	}
}

func TestConfigureIsIdempotentAndRefreshKeepsOverrides(t *testing.T) {
	f := newFixture(t)
	f.configure(t)
	f.configure(t)
	user, err := os.ReadFile(f.user)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(user), filepath.Join(f.dir, "ssh_config")) != 1 || strings.Count(string(user), f.brev) != 1 {
		t.Fatalf("duplicate includes:\n%s", user)
	}
	f.writeBrev(t, "192.0.2.11", "2222")
	got := sshConfig(t, f.user, f.target.Alias)
	if !strings.Contains(got, "hostname 192.0.2.11\n") || !strings.Contains(got, "stricthostkeychecking true\n") {
		t.Fatal("refresh did not preserve transport override and update gateway")
	}
}

func TestConfigureRejectsUntrustedTargetsBeforeWriting(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*fixture)
	}{
		{"hostname destination", func(f *fixture) { f.target.Address = "evil.example:22" }},
		{"wildcard alias", func(f *fixture) { f.target.Alias = "*" }},
		{"argument injection", func(f *fixture) { f.target.ID = "id;echo-pwned" }},
		{"missing pins", func(f *fixture) { f.target.HostKeys = nil }},
		{"invalid key", func(f *fixture) { f.target.HostKeys = []string{"ssh-ed25519 invalid"} }},
		{"unknown alias", func(f *fixture) { f.target.Alias = "missing" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.edit(&f)
			if err := Configure(f.dir, f.user, f.brev, f.binary, f.target); err == nil {
				t.Fatal("invalid target accepted")
			}
			if _, err := os.Stat(f.user); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid target mutated user SSH config")
			}
		})
	}
}

func TestConfigureRejectsLegacyAndCloudflaredAliases(t *testing.T) {
	for _, config := range []string{
		"Host training\n  HostName 192.0.2.1\n",
		"Match host training exec \"/bin/true mint-cert --environment test\"\n  ProxyCommand cloudflared access ssh\n",
	} {
		f := newFixture(t)
		if err := os.WriteFile(f.brev, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		if err := Configure(f.dir, f.user, f.brev, f.binary, f.target); err == nil {
			t.Fatal("unsupported alias accepted")
		}
	}
}

func TestUnknownTargetAndSymlinkAreRejected(t *testing.T) {
	f := newFixture(t)
	f.configure(t)
	if _, err := LoadTarget(f.dir, "100.73.1.3:22"); err == nil {
		t.Fatal("unconfigured destination accepted")
	}
	if err := os.Remove(filepath.Join(f.dir, manifestName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.brev, filepath.Join(f.dir, manifestName)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTargets(f.dir); err == nil {
		t.Fatal("symlink manifest accepted")
	}
}

func TestHostKeyPinIsIndependentOfGatewayPort(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH is required for host-key verification")
	}
	f := newFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	f.writeBrev(t, "127.0.0.1", port)
	f.configure(t)
	server := &ssh.ServerConfig{NoClientAuth: true}
	server.AddHostKey(f.signer)
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		conn, channels, requests, err := ssh.NewServerConn(connection, server)
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				done <- err
				return
			}
			for request := range requests {
				if request.Type == "exec" {
					_ = request.Reply(true, nil)
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					_ = channel.Close()
					done <- nil
					return
				}
				_ = request.Reply(false, nil)
			}
		}
		done <- fmt.Errorf("SSH session channel was not opened")
	}()
	output, err := exec.Command("ssh", "-T", "-F", f.user, "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", f.target.Alias, "true").CombinedOutput()
	if err != nil {
		t.Fatalf("pinned SSH connection: %v\n%s", err, output)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
