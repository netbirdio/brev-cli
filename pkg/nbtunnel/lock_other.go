//go:build !unix

package nbtunnel

// lock is a no-op where advisory file locks are unavailable.
func lock(_ string) (func(), error) {
	return func() {}, nil
}
