//go:build linux || darwin

package nbembed

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var errLocked = errors.New("another process is using this device identity")

func secureDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("device state directory must be an absolute path")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("device state path must be a directory, not a symlink")
	}
	if err := checkOwner(st); err != nil {
		return err
	}
	if st.Mode().Perm() != 0700 {
		return errors.New("device state directory must have permissions 0700")
	}
	return nil
}

func checkOwner(st os.FileInfo) error {
	info, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(info.Uid) != os.Geteuid() {
		return errors.New("device state must be owned by the current user")
	}
	return nil
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("device state files must be regular files with permissions 0600")
	}
	if err := checkOwner(st); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("device state file is too large")
	}
	return data, nil
}

func acquireLock(dir, name string) (*os.File, error) {
	fd, err := syscall.Open(filepath.Join(dir, name), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	fail := func(err error) (*os.File, error) { f.Close(); return nil, err }
	st, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return fail(errors.New("invalid device lock permissions"))
	}
	if err := checkOwner(st); err != nil {
		return fail(err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return fail(errLocked)
		}
		return fail(err)
	}
	return f, nil
}

func lockUntil(ctx context.Context, dir, name string) (*os.File, error) {
	for {
		f, err := acquireLock(dir, name)
		if !errors.Is(err, errLocked) {
			return f, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(30 * time.Millisecond):
		}
	}
}

// Enroll provisions a distinct identity in a child so login is forcibly bounded.
// The setup key is sent only through stdin and is never persisted by this package.
func Enroll(ctx context.Context, dir, managementURL, deviceName, setupKey string) error {
	if err := secureDir(dir); err != nil {
		return err
	}
	p := profileInfo{ManagementURL: managementURL, DeviceName: deviceName}
	if err := validateProfile(p); err != nil {
		return err
	}
	if setupKey == "" {
		return errors.New("a setup key is required for enrollment")
	}
	data, _ := json.Marshal(enrollmentRequest{ManagementURL: managementURL, DeviceName: deviceName, SetupKey: setupKey})
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "nb-agent", "--enroll", "--state-dir", dir)
	cmd.Stdin = bytes.NewReader(data)
	// Never relay upstream authentication errors that could contain credentials.
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("device enrollment timed out or was canceled: %w", ctx.Err())
		}
		return errors.New("device enrollment failed; check the management URL, setup key and device policy")
	}
	return nil
}

// RunEnrollment is the isolated nb-agent enrollment entry point.
func RunEnrollment(ctx context.Context, dir string, in io.Reader) error {
	if err := secureDir(dir); err != nil {
		return err
	}
	r, err := decodeEnrollment(in)
	if err != nil {
		return err
	}
	lock, err := acquireLock(dir, "identity.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := os.Lstat(filepath.Join(dir, "profile.json")); err == nil {
		return errors.New("this device is already enrolled; forget it before enrolling again")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	p := profileInfo{ManagementURL: r.ManagementURL, DeviceName: r.DeviceName}
	client, err := newEmbeddedEngine(dir, p, r.SetupKey)
	r.SetupKey = ""
	if err != nil {
		return err
	}
	if err := startBounded(ctx, client, startupTimeout); err != nil {
		return err
	}
	defer stopEngine(client)
	return writePrivateJSON(filepath.Join(dir, "profile.json"), p)
}

// Serve runs the one embedded peer for this OS user's profile. Call it only in
// the nb-agent child process: returning from a timed-out Start must exit that process.
func Serve(ctx context.Context, dir string) error { return serve(ctx, dir, newEmbeddedEngine) }

func startBounded(ctx context.Context, e engine, timeout time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	startCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Start(startCtx) }()
	select {
	case <-startCtx.Done():
		return fmt.Errorf("secure connection startup canceled or timed out: %w", startCtx.Err())
	case err := <-done:
		if err != nil {
			return errors.New("could not connect this device to NetBird management")
		}
		return nil
	}
}

func stopEngine(e engine) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = e.Stop(ctx); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func serve(ctx context.Context, dir string, newEngine engineFactory) error {
	if err := secureDir(dir); err != nil {
		return err
	}
	lock, err := acquireLock(dir, "identity.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	profile, err := readProfile(dir)
	if err != nil {
		return err
	}
	e, err := newEngine(dir, profile, "")
	if err != nil {
		return err
	}
	socketPath := filepath.Join(dir, "agent.sock")
	if st, err := os.Lstat(socketPath); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return errors.New("helper socket path is occupied by a non-socket file")
		}
		if err := checkOwner(st); err != nil {
			return err
		}
		if err := os.Remove(socketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Publish stop/status IPC before login, which upstream can block without
	// honoring its caller's context. The isolated process exits when Serve
	// returns, including when a stop request interrupts that blocked login.
	startup := &startupState{done: make(chan struct{})}
	go func() {
		startup.err = startBounded(ctx, e, helperStartupTimeout)
		close(startup.done)
		if startup.err != nil {
			cancel()
		}
	}()
	defer func() {
		if startup.ready() {
			stopEngine(e)
		}
	}()
	var connections sync.Map
	var workers sync.WaitGroup
	var activityMu sync.Mutex
	activeConnections := 0
	lastActivity := time.Now()
	closeConnections := func() {
		listener.Close()
		connections.Range(func(key, value any) bool { key.(net.Conn).Close(); return true })
	}
	closeOnCancel := context.AfterFunc(ctx, closeConnections)
	defer func() {
		cancel()
		closeOnCancel()
		closeConnections()
		workers.Wait()
	}()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				activityMu.Lock()
				expired := activeConnections == 0 && time.Since(lastActivity) >= idleTimeout
				if expired {
					cancel()
				}
				activityMu.Unlock()
				if expired {
					return
				}
			}
		}
	}()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			cancel()
			return err
		}
		connections.Store(conn, struct{}{})
		activityMu.Lock()
		activeConnections++
		activityMu.Unlock()
		if ctx.Err() != nil {
			conn.Close()
			connections.Delete(conn)
			activityMu.Lock()
			activeConnections--
			activityMu.Unlock()
			return nil
		}
		workers.Add(1)
		go func() {
			defer func() {
				activityMu.Lock()
				activeConnections--
				lastActivity = time.Now()
				activityMu.Unlock()
			}()
			defer workers.Done()
			defer connections.Delete(conn)
			defer conn.Close()
			handleConnection(ctx, cancel, dir, profile, e, startup, conn)
		}()
	}
}

func handleConnection(ctx context.Context, stop context.CancelFunc, dir string, p profileInfo, e engine, startup *startupState, conn *net.UnixConn) {
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))
	reader := bufio.NewReader(conn)
	var req request
	if err := readFrame(reader, &req); err != nil {
		return
	}
	reply := func(r response) error { return json.NewEncoder(conn).Encode(r) }
	switch req.Operation {
	case "status":
		_ = reply(response{OK: true, Status: StatusInfo{Enrolled: true, Running: true, Ready: startup.ready(), ManagementURL: p.ManagementURL, DeviceName: p.DeviceName}})
	case "stop":
		_ = reply(response{OK: true})
		stop()
	case "dial":
		address, err := targetAddress(dir, req.TargetID)
		if err != nil {
			_ = reply(response{Error: err.Error()})
			return
		}
		dialCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		defer cancel()
		select {
		case <-dialCtx.Done():
			_ = reply(response{Error: "secure connection startup canceled or timed out"})
			return
		case <-startup.done:
			if startup.err != nil {
				_ = reply(response{Error: "secure connection helper could not connect to management"})
				return
			}
		}
		remote, err := e.Dial(dialCtx, "tcp", address)
		if err != nil {
			_ = reply(response{Error: "direct SSH is unavailable; the peer may be offline or policy may deny access"})
			return
		}
		defer remote.Close()
		if err := reply(response{OK: true}); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})
		closeRemote := context.AfterFunc(ctx, func() { remote.Close() })
		defer closeRemote()
		bridge(conn, reader, remote)
	default:
		_ = reply(response{Error: "unknown helper operation"})
	}
}

func bridge(local net.Conn, reader io.Reader, remote net.Conn) {
	done := make(chan struct{})
	go func() {
		_, err := io.Copy(remote, reader)
		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else if err != nil {
			remote.Close()
		}
		close(done)
	}()
	_, _ = io.Copy(local, remote)
	// Closing the completed remote stream also releases an input writer that
	// would otherwise remain blocked after the server stopped reading stdin.
	_ = remote.Close()
	if cw, ok := local.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	// The remote session finished; release a blocked stdin reader as well.
	if cr, ok := local.(interface{ CloseRead() error }); ok {
		_ = cr.CloseRead()
	} else {
		local.Close()
	}
	<-done
}

func readFrame(reader *bufio.Reader, out any) error {
	data, err := reader.ReadSlice('\n')
	if err != nil {
		return errors.New("invalid helper response")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("invalid helper message")
	}
	return nil
}

func connect(ctx context.Context, dir string, req request) (*net.UnixConn, *bufio.Reader, response, error) {
	var result response
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, "agent.sock"))
	if err != nil {
		return nil, nil, result, err
	}
	local := conn.(*net.UnixConn)
	closeOnCancel := context.AfterFunc(ctx, func() { local.Close() })
	defer closeOnCancel()
	deadline := time.Now().Add(requestTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = local.SetDeadline(deadline)
	if err := json.NewEncoder(local).Encode(req); err != nil {
		local.Close()
		return nil, nil, result, err
	}
	reader := bufio.NewReader(local)
	if err := readFrame(reader, &result); err != nil {
		local.Close()
		return nil, nil, result, err
	}
	if !result.OK {
		local.Close()
		return nil, nil, result, errors.New(result.Error)
	}
	if !closeOnCancel() {
		local.Close()
		return nil, nil, result, ctx.Err()
	}
	_ = local.SetDeadline(time.Time{})
	return local, reader, result, nil
}

type bufferedConn struct {
	*net.UnixConn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// Dial opens a byte stream only to a configured target ID. It starts the helper
// on demand; it never enrolls a device, prompts, or falls back to a gateway.
func Dial(ctx context.Context, dir, targetID string) (net.Conn, error) {
	if err := secureDir(dir); err != nil {
		return nil, err
	}
	if _, err := targetAddress(dir, targetID); err != nil {
		return nil, err
	}
	if err := ensureRunning(ctx, dir); err != nil {
		return nil, err
	}
	conn, reader, _, err := connect(ctx, dir, request{Operation: "dial", TargetID: targetID})
	if err != nil {
		return nil, err
	}
	return &bufferedConn{UnixConn: conn, reader: reader}, nil
}

func ensureRunning(ctx context.Context, dir string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := readProfile(dir); err != nil {
		return err
	}
	probe := func() bool {
		probeCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		conn, _, result, err := connect(probeCtx, dir, request{Operation: "status"})
		if err != nil {
			return false
		}
		conn.Close()
		return result.Status.Ready
	}
	if probe() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, helperStartupTimeout)
	defer cancel()
	lock, err := lockUntil(ctx, dir, "launch.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	if probe() {
		return nil
	}
	// An explicitly launched helper can own the identity before it opens IPC.
	// Wait for that owner instead of launching a competing engine process.
	identityLock, identityErr := acquireLock(dir, "identity.lock")
	if errors.Is(identityErr, errLocked) {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			if probe() {
				return nil
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("another helper owns this identity but is not ready: %w", ctx.Err())
			case <-ticker.C:
			}
		}
	}
	if identityErr != nil {
		return identityErr
	}
	identityLock.Close()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(executable, "nb-agent", "--state-dir", dir)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, io.Discard, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start secure connection helper: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if probe() {
			return nil
		}
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			<-exited
			return fmt.Errorf("secure connection helper startup: %w", ctx.Err())
		case <-exited:
			return errors.New("secure connection helper could not start; check device enrollment and connectivity")
		case <-ticker.C:
		}
	}
}

// Status reports enrollment and the existing helper without starting it.
func Status(ctx context.Context, dir string) (StatusInfo, error) {
	var s StatusInfo
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err := secureDir(dir); err != nil {
		return s, err
	}
	p, err := readProfile(dir)
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(dir, "profile.json")); errors.Is(statErr, os.ErrNotExist) {
			return s, nil
		}
		return s, err
	}
	s = StatusInfo{Enrolled: true, ManagementURL: p.ManagementURL, DeviceName: p.DeviceName}
	conn, _, r, err := connect(ctx, dir, request{Operation: "status"})
	if err == nil {
		conn.Close()
		return r.Status, nil
	}
	if ctx.Err() != nil {
		return s, ctx.Err()
	}
	return s, nil
}

// Stop closes all helper-owned streams without claiming to revoke the peer.
func Stop(ctx context.Context, dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := secureDir(dir); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, shutdownTimeout+time.Second)
	defer cancel()
	conn, _, _, err := connect(ctx, dir, request{Operation: "stop"})
	if err == nil {
		conn.Close()
	}
	lock, lockErr := lockUntil(ctx, dir, "identity.lock")
	if lockErr != nil {
		return fmt.Errorf("helper did not stop: %w", lockErr)
	}
	lock.Close()
	return nil
}

// Forget removes only this helper's local identity. The management peer must
// also be deleted by an administrator to revoke copies of that identity.
func Forget(ctx context.Context, dir string) error {
	if err := Stop(ctx, dir); err != nil {
		return err
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	lock, err := acquireLock(dir, "identity.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	for _, name := range []string{"profile.json", "netbird.json", "state.json"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
