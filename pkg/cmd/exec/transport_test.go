package exec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPilotExecDoesNotRepeatFailedRemoteCommand(t *testing.T) {
	dir := t.TempDir()
	counter := filepath.Join(dir, "invocations")
	fakeSSH := "#!/bin/sh\nprintf 'called\\n' >> \"$BREV_TEST_INVOCATIONS\"\nexit 17\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(fakeSSH), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(dir, "unused-agent"))
	t.Setenv("BREV_TEST_INVOCATIONS", counter)
	original := isPilotTarget
	isPilotTarget = func(alias string) bool { return alias == "gpu" }
	t.Cleanup(func() { isPilotTarget = original })
	// Nil stores deliberately fail if the command enters the legacy retry path.
	if err := runExecCommand(nil, nil, "gpu", false, "exit 17"); err == nil {
		t.Fatal("expected failed remote command")
	}
	data, err := os.ReadFile(counter)
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(data), "called\n"); count != 1 {
		t.Fatalf("remote command executed %d times, want once", count)
	}
}
