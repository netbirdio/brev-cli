package nbagent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestEnrollmentDoesNotExposeCredentials(t *testing.T) {
	t.Setenv("BREV_EXPERIMENTAL_NETBIRD", "1")
	cmd := newCmdNBAgent(agentDeps{enroll: func(_ context.Context, _ string, in io.Reader) error {
		secret, _ := io.ReadAll(in)
		return errors.New(string(secret))
	}})
	cmd.SetArgs([]string{"--state-dir", "/state", "--enroll"})
	cmd.SetIn(strings.NewReader("secret-value"))
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	if err == nil || strings.Contains(err.Error()+out.String(), "secret-value") {
		t.Fatal("enrollment error leaked credentials")
	}
}

func TestExistingHelperStartsWithoutExperimentalFlag(t *testing.T) {
	t.Setenv("BREV_EXPERIMENTAL_NETBIRD", "")
	called := false
	cmd := newCmdNBAgent(agentDeps{serve: func(_ context.Context, dir string) error { called = dir == "/state"; return nil }})
	cmd.SetArgs([]string{"--state-dir", "/state"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil || !called || out.Len() != 0 {
		t.Fatalf("helper start failed or polluted stdout: %v %q", err, out.String())
	}
}
