package shell

import (
	"net/netip"
	"strings"
	"testing"

	nodev1 "buf.build/gen/go/brevdev/devplane/protocolbuffers/go/devplaneapi/v1"
)

func TestNetbirdSSHOptions(t *testing.T) {
	target := meshTarget{addr: netip.MustParseAddr("100.73.1.2"), port: 2222}
	got := netbirdSSHOptions("/opt/brev bin/brev", target)
	want := []string{
		"-o", "ProxyCommand='/opt/brev bin/brev' nb-proxy 100.73.1.2 2222",
		"-o", "ProxyJump=none",
		"-o", "ConnectTimeout=90",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("options = %q, want %q", got, want)
	}
	for _, o := range got {
		if strings.HasPrefix(o, "HostName=") || strings.HasPrefix(o, "Port=") {
			t.Errorf("HostName and Port must not be overridden, they break 'Match host <alias>': %q", o)
		}
	}
}

func TestSSHServerPort(t *testing.T) {
	ports := []*nodev1.Port{
		{PortId: "port_ssh", PortNumber: 41920, ServerPort: 2222},
		{PortId: "port_zero", PortNumber: 41921, ServerPort: 0},
	}
	tests := []struct {
		name   string
		portID string
		want   uint16
	}{
		{name: "reported server port", portID: "port_ssh", want: 2222},
		{name: "server port not reported", portID: "port_zero", want: 22},
		{name: "unknown port id", portID: "port_missing", want: 22},
		{name: "no access port", portID: "", want: 22},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sshServerPort(ports, tt.portID); got != tt.want {
				t.Errorf("sshServerPort(%q) = %d, want %d", tt.portID, got, tt.want)
			}
		})
	}
}

func TestParseMeshAddr(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    netip.Addr
		wantErr string
	}{
		{name: "plain address", raw: "100.73.1.2", want: netip.MustParseAddr("100.73.1.2")},
		{name: "address with prefix", raw: "100.73.1.2/16", want: netip.MustParseAddr("100.73.1.2")},
		{name: "mapped address is unmapped", raw: "::ffff:100.73.1.2", want: netip.MustParseAddr("100.73.1.2")},
		{name: "missing address names the mesh", raw: "", wantErr: "mesh"},
		{name: "garbage", raw: "not-an-ip", wantErr: "parse NetBird address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMeshAddr(tt.raw, "my-instance")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("addr = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestMeshTargetHostPort(t *testing.T) {
	m := meshTarget{addr: netip.MustParseAddr("100.73.1.2"), port: 2222}
	if got := m.hostPort(); got != "100.73.1.2:2222" {
		t.Errorf("hostPort() = %q, want 100.73.1.2:2222", got)
	}
}
