//go:build linux

package bgp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// gtsmTTL is the TTL sent and required by GTSM, as described in RFC 5082,
// section 3.
const gtsmTTL = 255

// setMD5 installs a TCP-MD5 (RFC 2385) key for peer on the socket underlying
// c. An empty password removes any key previously installed for peer.
//
// Keys are installed for the peer's exact address. An IPv6 link-local peer
// must carry a zone, which is resolved into the sockaddr's scope, so that
// BGP unnumbered peering over fe80::/10 works. TCP_MD5SIG_EXT is not used:
// its prefix keys (TCP_MD5SIG_FLAG_PREFIX) have no exact-address use, and
// its interface binding (TCP_MD5SIG_FLAG_IFINDEX) scopes a key to an L3
// master (VRF) device rather than to a link — VRF support can be added
// without changing this contract.
func setMD5(c syscall.RawConn, peer netip.Addr, password string) error {
	if len(password) > unix.TCP_MD5SIG_MAXKEYLEN {
		return fmt.Errorf("bgp: TCP-MD5 password is longer than %d bytes",
			unix.TCP_MD5SIG_MAXKEYLEN)
	}

	// A zero length key removes the key installed for peer, if any.
	sig := unix.TCPMD5Sig{Keylen: uint16(len(password))}
	copy(sig.Key[:], password)

	// The key is addressed by a sockaddr of the peer's family, stored in the
	// generic storage at the head of the structure.
	if peer.Is4() {
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&sig.Addr))
		sa.Family = unix.AF_INET
		sa.Addr = peer.As4()
	} else {
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(&sig.Addr))
		sa.Family = unix.AF_INET6
		sa.Addr = peer.As16()

		switch zone := peer.Zone(); {
		case zone != "":
			idx, err := zoneIndex(zone)
			if err != nil {
				return err
			}

			sa.Scope_id = uint32(idx)
		case peer.IsLinkLocalUnicast():
			// Without a zone the key is ambiguous across links, and a key
			// installed anyway may silently fail to match.
			return fmt.Errorf("bgp: TCP-MD5 with a link-local peer requires a zone: %s", peer)
		}
	}

	return control(c, func(fd int) error {
		return unix.SetsockoptTCPMD5Sig(fd, unix.IPPROTO_TCP, unix.TCP_MD5SIG, &sig)
	})
}

// acceptTransient classifies an accept failure which is not listener
// death: abort reports a single connection the kernel aborted before it
// was accepted (retry immediately), and exhausted reports file descriptor
// exhaustion, which recovers as sessions close (retry after a pause).
func acceptTransient(err error) (abort, exhausted bool) {
	if errors.Is(err, unix.ECONNABORTED) {
		return true, false
	}

	if errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE) {
		return false, true
	}

	return false, false
}

// zoneIndex resolves an IPv6 zone, an interface name or index in string
// form, to an interface index.
func zoneIndex(zone string) (int, error) {
	if ifi, err := net.InterfaceByName(zone); err == nil {
		return ifi.Index, nil
	}

	if idx, err := strconv.Atoi(zone); err == nil && idx > 0 {
		return idx, nil
	}

	return 0, fmt.Errorf("bgp: cannot resolve IPv6 zone %q to an interface", zone)
}

// setGTSM enables GTSM (RFC 5082) on the socket underlying c, which belongs
// to the IPv4 address family when ipv4 is true and IPv6 otherwise. Both
// directions are configured: outgoing packets carry a TTL of 255, and
// incoming packets with a lower TTL are dropped by the kernel.
func setGTSM(c syscall.RawConn, ipv4 bool) error {
	level, ttl, minTTL := unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, unix.IPV6_MINHOPCOUNT
	if ipv4 {
		level, ttl, minTTL = unix.IPPROTO_IP, unix.IP_TTL, unix.IP_MINTTL
	}

	return control(c, func(fd int) error {
		if err := unix.SetsockoptInt(fd, level, ttl, gtsmTTL); err != nil {
			return err
		}

		return unix.SetsockoptInt(fd, level, minTTL, gtsmTTL)
	})
}

// setDSCP marks packets sent from the socket underlying c with the six bit
// code point dscp, which belongs to the IPv4 address family when ipv4 is
// true and IPv6 otherwise. Both families carry the code point in the upper
// six bits of an octet: the IPv4 TOS byte and the IPv6 traffic class. The
// kernel preserves the two ECN bits below it on a TCP socket.
func setDSCP(c syscall.RawConn, ipv4 bool, dscp uint8) error {
	level, opt := unix.IPPROTO_IPV6, unix.IPV6_TCLASS
	if ipv4 {
		level, opt = unix.IPPROTO_IP, unix.IP_TOS
	}

	return control(c, func(fd int) error {
		return unix.SetsockoptInt(fd, level, opt, int(dscp)<<2)
	})
}

// setUserTimeout bounds the time transmitted data may remain unacknowledged
// on the socket underlying c to d (TCP_USER_TIMEOUT), which must be positive
// and is rounded up to a whole millisecond: the kernel's unit, and one below
// which a nonzero d would otherwise round to "disabled".
func setUserTimeout(c syscall.RawConn, d time.Duration) error {
	ms := (d + time.Millisecond - 1) / time.Millisecond
	return control(c, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(ms))
	})
}

// setBuffer sets the size in bytes of the send buffer (SO_SNDBUF) of the
// socket underlying c when send is true, and of its receive buffer
// (SO_RCVBUF) otherwise. The kernel reserves as much again for its own
// bookkeeping, so reading the option back reports twice the value set, and
// it clamps the value to net.core.wmem_max or net.core.rmem_max.
func setBuffer(c syscall.RawConn, send bool, size int) error {
	opt := unix.SO_RCVBUF
	if send {
		opt = unix.SO_SNDBUF
	}

	return control(c, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.SOL_SOCKET, opt, size)
	})
}

// control invokes fn with the file descriptor underlying c, reporting any
// error raised by either the control operation or fn itself.
func control(c syscall.RawConn, fn func(fd int) error) error {
	var err error
	doErr := c.Control(func(fd uintptr) {
		err = fn(int(fd))
	})
	if doErr != nil {
		return doErr
	}

	if err != nil {
		// The package prefix is applied here because this error escapes
		// verbatim through Listener.SetMD5 and its siblings; the dialed
		// path wraps it in a net.OpError with its own context.
		return fmt.Errorf("bgp: %w", os.NewSyscallError("setsockopt", err))
	}

	return nil
}
