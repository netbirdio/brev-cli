//go:build !linux && !darwin

package nbembed

import (
	"context"
	"errors"
	"io"
	"net"
)

var errUnsupported = errors.New("embedded SSH transport supports Linux, macOS, and WSL; native Windows is not supported")

func Enroll(context.Context, string, string, string, string) error { return errUnsupported }
func RunEnrollment(context.Context, string, io.Reader) error       { return errUnsupported }
func Serve(context.Context, string) error                          { return errUnsupported }
func Dial(context.Context, string, string) (net.Conn, error)       { return nil, errUnsupported }
func Stop(context.Context, string) error                           { return errUnsupported }
func Forget(context.Context, string) error                         { return errUnsupported }
func Status(context.Context, string) (StatusInfo, error)           { return StatusInfo{}, errUnsupported }
func readPrivateFile(string, int64) ([]byte, error)                { return nil, errUnsupported }
