package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/brevdev/brev-cli/pkg/nbembed"
	"github.com/brevdev/brev-cli/pkg/sshtransport"
	"github.com/spf13/cobra"
)

func execute(t *testing.T, deps dependencies, input string, args ...string) (string, error) {
	t.Helper()
	if deps.defaultDir == nil {
		deps.defaultDir = func() (string, error) { return "/test/state", nil }
	}
	if deps.status == nil {
		deps.status = func(context.Context, string) (nbembed.StatusInfo, error) { return nbembed.StatusInfo{}, nil }
	}
	cmd := newCmdTunnel(deps)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestEnrollmentRequiresOptInBeforeReadingKey(t *testing.T) {
	t.Setenv(experimentalEnv, "")
	called := false
	_, err := execute(t, dependencies{enroll: func(context.Context, string, string, string, string) error { called = true; return nil }}, "secret", "enroll", "--management-url", "https://management.example", "--setup-key-stdin")
	if err == nil || called {
		t.Fatal("enrollment must be blocked without experimental opt-in")
	}
}

func TestEnrollmentPassesKeyOnlyAsInputAndSanitizesErrors(t *testing.T) {
	t.Setenv(experimentalEnv, "1")
	const secret = "one-use-secret"
	deps := dependencies{enroll: func(_ context.Context, dir, endpoint, name, key string) error {
		if dir != "/test/state" || endpoint != "https://management.example" || name != "laptop" || key != secret {
			t.Fatal("wrong enrollment inputs")
		}
		return fmt.Errorf("upstream leaked %s", key)
	}}
	out, err := execute(t, deps, secret+"\n", "enroll", "--management-url", "https://management.example", "--name", "laptop", "--setup-key-stdin")
	if err == nil {
		t.Fatal("expected enrollment error")
	}
	if strings.Contains(out+err.Error(), secret) {
		t.Fatal("setup key escaped into output or returned error")
	}
}

func TestEnrollmentRejectsUnsafeEndpoint(t *testing.T) {
	t.Setenv(experimentalEnv, "1")
	for _, endpoint := range []string{"http://management.example", "https://user:secret@management.example", "https://management.example?key=secret"} {
		_, err := execute(t, dependencies{}, "key", "enroll", "--management-url", endpoint, "--setup-key-stdin")
		if err == nil {
			t.Fatalf("accepted unsafe endpoint %q", endpoint)
		}
	}
}

func TestEnrollmentDefaultsDeviceName(t *testing.T) {
	t.Setenv(experimentalEnv, "1")
	called := false
	deps := dependencies{enroll: func(_ context.Context, _, _, name, _ string) error {
		called = true
		if strings.TrimSpace(name) == "" {
			t.Fatal("default device name is empty")
		}
		return nil
	}}
	_, err := execute(t, deps, "key", "enroll", "--management-url", "https://management.example", "--setup-key-stdin")
	if err != nil || !called {
		t.Fatalf("enrollment without --name failed: %v", err)
	}
}

func TestConfigureCarriesOnlyExplicitTrustedHostKeys(t *testing.T) {
	t.Setenv(experimentalEnv, "1")
	called := false
	deps := dependencies{
		readKeys: func(path string) ([]string, error) {
			if path != "trusted.pub" {
				t.Fatal(path)
			}
			return []string{"ssh-ed25519 trusted"}, nil
		},
		paths: func(string) (string, string, string, error) { return "/user/ssh", "/brev/ssh", "/bin/brev", nil },
		configure: func(dir, user, brev, exe string, target sshtransport.Target) error {
			called = true
			if target.ID != "gpu" || target.Alias != "gpu" || target.Address != "100.73.1.2:22" || target.HostKeyAlias != "gpu" || len(target.HostKeys) != 1 {
				t.Fatalf("unexpected target: %#v", target)
			}
			if user != "/user/ssh" || brev != "/brev/ssh" || exe != "/bin/brev" {
				t.Fatal("wrong paths")
			}
			return nil
		},
	}
	_, err := execute(t, deps, "", "configure", "gpu", "--address", "100.73.1.2:22", "--host-key-file", "trusted.pub")
	if err != nil || !called {
		t.Fatalf("configure failed: %v", err)
	}
}

func TestGatewayRollbackDoesNotRequireFeatureFlag(t *testing.T) {
	t.Setenv(experimentalEnv, "")
	called := ""
	deps := dependencies{use: func(_ string, mode string) error { called = mode; return nil }}
	if _, err := execute(t, deps, "", "use", "direct"); err == nil || called != "" {
		t.Fatal("direct enabled without opt-in")
	}
	if _, err := execute(t, deps, "", "use", "gateway"); err != nil || called != "gateway" {
		t.Fatalf("gateway rollback failed: %v", err)
	}
}

func TestDirectRequiresEnrolledIdentity(t *testing.T) {
	t.Setenv(experimentalEnv, "1")
	called := false
	deps := dependencies{use: func(string, string) error { called = true; return nil }}
	_, err := execute(t, deps, "", "use", "direct")
	if err == nil || called {
		t.Fatal("direct preference enabled without a local identity")
	}
}

func TestExistingEnrollmentIsNotReplaced(t *testing.T) {
	t.Setenv(experimentalEnv, "1")
	called := false
	deps := dependencies{
		status: func(context.Context, string) (nbembed.StatusInfo, error) {
			return nbembed.StatusInfo{Enrolled: true}, nil
		},
		enroll: func(context.Context, string, string, string, string) error { called = true; return nil },
	}
	_, err := execute(t, deps, "key", "enroll", "--management-url", "https://management.example", "--setup-key-stdin")
	if err == nil || called || !strings.Contains(err.Error(), "already enrolled") {
		t.Fatalf("unexpected duplicate enrollment result: %v", err)
	}
}

func TestCleanupForgetsIdentityEvenWhenConfigFails(t *testing.T) {
	want := errors.New("config read-only")
	forgot := false
	err := cleanupLocal(context.Background(), "/state", func(string, string) error { return want }, func(context.Context, string) error { forgot = true; return nil })
	if !errors.Is(err, want) || !forgot {
		t.Fatal("cleanup must attempt identity removal and retain configuration error")
	}
	err = cleanupLocal(context.Background(), "/state", func(string, string) error { return os.ErrNotExist }, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal("absent profile should not block logout")
	}
}

func TestForgetReportsRemoteRevocationStillRequired(t *testing.T) {
	t.Setenv(experimentalEnv, "")
	forgot := false
	deps := dependencies{
		status: func(context.Context, string) (nbembed.StatusInfo, error) {
			return nbembed.StatusInfo{Enrolled: true, DeviceName: "laptop", ManagementURL: "https://management.example"}, nil
		},
		use: func(_ string, mode string) error {
			if mode != "gateway" {
				t.Fatal("forget must select gateway")
			}
			return nil
		},
		forget: func(context.Context, string) error { forgot = true; return nil },
	}
	out, err := execute(t, deps, "", "forget")
	if err != nil || !forgot || !strings.Contains(out, "Remote revocation is not complete") || !strings.Contains(out, `"laptop"`) {
		t.Fatalf("forget lost revocation guidance: %v %q", err, out)
	}
}

func TestTunnelSkipsParentHooks(t *testing.T) {
	parent := &cobra.Command{Use: "brev", PersistentPreRunE: func(*cobra.Command, []string) error { t.Fatal("parent pre-run invoked"); return nil }, PersistentPostRunE: func(*cobra.Command, []string) error { t.Fatal("parent post-run invoked"); return nil }}
	parent.AddCommand(newCmdTunnel(dependencies{defaultDir: func() (string, error) { return "/state", nil }, stop: func(context.Context, string) error { return nil }}))
	parent.SetArgs([]string{"tunnel", "stop"})
	parent.SetOut(&bytes.Buffer{})
	if err := parent.Execute(); err != nil {
		t.Fatal(err)
	}
}
