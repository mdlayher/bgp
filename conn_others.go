//go:build !linux

package bgp

import (
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"time"
)

// setMD5 is not implemented on this platform.
func setMD5(_ syscall.RawConn, _ netip.Addr, _ string) error {
	return fmt.Errorf("bgp: TCP-MD5 is not supported on this platform: %w",
		errors.ErrUnsupported)
}

// setGTSM is not implemented on this platform.
func setGTSM(_ syscall.RawConn, _ bool) error {
	return fmt.Errorf("bgp: GTSM is not supported on this platform: %w",
		errors.ErrUnsupported)
}

// setDSCP is not implemented on this platform.
func setDSCP(_ syscall.RawConn, _ bool, _ uint8) error {
	return fmt.Errorf("bgp: DSCP is not supported on this platform: %w",
		errors.ErrUnsupported)
}

// setUserTimeout is not implemented on this platform.
func setUserTimeout(_ syscall.RawConn, _ time.Duration) error {
	return fmt.Errorf("bgp: TCP user timeout is not supported on this platform: %w",
		errors.ErrUnsupported)
}

// setBuffer is not implemented on this platform.
func setBuffer(_ syscall.RawConn, _ bool, _ int) error {
	return fmt.Errorf("bgp: socket buffer sizing is not supported on this platform: %w",
		errors.ErrUnsupported)
}

// acceptTransient reports no transient accept errors on this platform:
// without portable errno semantics, every accept failure is treated as
// listener death.
func acceptTransient(_ error) (abort, exhausted bool) {
	return false, false
}
