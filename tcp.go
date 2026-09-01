package bgp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// Port is the well-known TCP port for BGP, as assigned by IANA. A Dialer
// dials it when its own Port field is zero.
const Port = 179

// useMultipathTCP determines whether this package's connections may use
// Multipath TCP (RFC 8684). They may not: BGP is a single-path control
// protocol, the net package enables MPTCP by default, and an MPTCP socket
// rejects every socket option a BGP speaker sets: TCP_MD5SIG, the TTL
// options behind GTSM, IP_TOS, and TCP_USER_TIMEOUT among them.
const useMultipathTCP = false

// DSCPCS6 is the Class Selector 6 Differentiated Services Code Point (RFC
// 2474). RFC 4594 assigns it to network control traffic, and routers
// conventionally apply it to BGP. It is the usual value for TCPOptions.DSCP.
const DSCPCS6 = 48

// maxDSCP is the largest DSCP value: the code point is six bits wide.
const maxDSCP = 63

// maxUserTimeout is the largest TCP_USER_TIMEOUT, which the kernel takes as
// an unsigned 32 bit count of milliseconds.
const maxUserTimeout = math.MaxUint32 * time.Millisecond

// TCPOptions carries the socket options a BGP speaker sets on both the active
// and the passive open. Embedded in Dialer, the options apply to each dialed
// connection. Embedded in ListenConfig, they apply to the listening socket,
// and every accepted connection inherits them. Each option is a whole-socket
// property: peers with different needs must be split across listeners. The
// zero value sets nothing.
//
// With the exception of KeepAlive, these options are only supported on Linux.
// Elsewhere, setting any of them makes [Dialer.Dial] and ListenConfig.Listen
// return an error which wraps [errors.ErrUnsupported].
type TCPOptions struct {
	// GTSM optionally enables the Generalized TTL Security Mechanism (RFC
	// 5082): outgoing packets are sent with a TTL of 255, and incoming
	// packets with a lower TTL are dropped by the kernel.
	//
	// GTSM only makes sense for a directly connected peer. Multihop peering
	// is its explicit opposite and needs no option at all, since the kernel
	// default TTL already crosses any reasonable multihop distance.
	GTSM bool

	// DSCP optionally marks outgoing packets with a Differentiated Services
	// Code Point (RFC 2474), a value from 0 to 63, so that routers along the
	// path can prioritize the session's traffic. The conventional marking
	// for BGP is DSCPCS6. The zero value leaves packets unmarked, which is
	// the kernel default.
	DSCP uint8

	// UserTimeout optionally bounds how long transmitted data may remain
	// unacknowledged before the kernel closes the connection
	// (TCP_USER_TIMEOUT). The failure surfaces on the next read or write.
	// The zero value leaves the kernel default, which gives up only after
	// tcp_retries2 exhausts: roughly fifteen minutes.
	//
	// UserTimeout is not a liveness mechanism; the BGP hold timer is, and
	// the FSM closes a session whose hold timer expires regardless of this
	// option. What UserTimeout buys is agreement between the kernel and
	// the session. Without it, a peer which stops acknowledging mid-write
	// keeps the kernel retransmitting long after BGP has declared the
	// session dead. Conventionally it is set to the hold time. The same
	// bound also caps how long TCP keepalive probes may go unanswered on
	// an idle connection, overriding the probe count.
	//
	// A positive value is rounded up to a whole millisecond. A negative
	// value is an error.
	UserTimeout time.Duration

	// SendBuffer optionally sets the size in bytes of the kernel's send
	// buffer (SO_SNDBUF). The zero value leaves the kernel to size the
	// buffer itself, adaptively. A nonzero value turns that off, and the
	// kernel may still round or clamp it. A negative value is an error.
	//
	// Operators tune the send buffer for the burst of a full-table push.
	// A larger buffer trades later detection of a stalled peer for
	// throughput. A write completes as soon as the kernel has buffered
	// it, so a larger buffer lets more of a push complete before a peer
	// which stopped reading becomes visible.
	SendBuffer int

	// RecvBuffer optionally sets the size in bytes of the kernel's
	// receive buffer (SO_RCVBUF), with SendBuffer's zero, rounding, and
	// negative-value semantics. It is set before the socket connects or
	// listens: the only point at which the buffer can influence the
	// window scale TCP negotiates.
	RecvBuffer int

	// KeepAlive optionally configures TCP keepalive probes. The nil value
	// leaves the net package's default, which enables probes at its own
	// idle time, interval, and count. A non-nil value with Enable set
	// replaces that configuration. A non-nil value with Enable clear
	// disables probes entirely.
	//
	// TCP keepalive is not BGP's liveness mechanism; the hold timer is,
	// and it detects a dead peer on its own. Probes are a backstop for
	// the one case the hold timer cannot see from inside the kernel: a
	// peer which vanished without a reset. The hold timer reports that
	// silence only when it expires, while probes can fail the connection
	// sooner. Callers who align the probes with the hold time should note
	// that UserTimeout, when set, caps unanswered probes as well.
	//
	// Unlike every other option, KeepAlive is portable and never yields
	// [errors.ErrUnsupported]: the net package applies it to dialed and
	// accepted connections alike.
	KeepAlive *net.KeepAliveConfig
}

// keepAlive applies o.KeepAlive to the net package's pair of keepalive fields,
// which Dialer and ListenConfig share. The pair's semantics are the net
// package's: the config is honored when its Enable is set, and probes are
// disabled only by a negative interval, not by a clear Enable.
//
// The option is the net package's to apply rather than this package's because
// it applies its own keepalive configuration to every accepted connection: a
// value set on the listening socket would not survive Accept.
func (o TCPOptions) keepAlive(interval *time.Duration, config *net.KeepAliveConfig) {
	switch {
	case o.KeepAlive == nil:
		return
	case o.KeepAlive.Enable:
		*config = *o.KeepAlive
	default:
		*interval = -1
	}
}

// check validates the options before any socket exists to apply them to.
func (o TCPOptions) check() error {
	if o.DSCP > maxDSCP {
		return fmt.Errorf("bgp: DSCP %d is not between 0 and %d", o.DSCP, maxDSCP)
	}

	if o.UserTimeout < 0 || o.UserTimeout > maxUserTimeout {
		return fmt.Errorf("bgp: user timeout %s is not between 0 and %s", o.UserTimeout, maxUserTimeout)
	}

	if o.SendBuffer < 0 {
		return fmt.Errorf("bgp: send buffer size %d is negative", o.SendBuffer)
	}

	if o.RecvBuffer < 0 {
		return fmt.Errorf("bgp: receive buffer size %d is negative", o.RecvBuffer)
	}

	return nil
}

// control applies the options to the socket underlying c, which belongs to
// the resolved network network. The IP-level options are each a level/option
// pair selected by address family, which the single-family network name
// decides; the TCP-level options are the same in both families.
func (o TCPOptions) control(network string, c syscall.RawConn) error {
	if o == (TCPOptions{}) {
		return nil
	}

	var ipv4 bool
	switch network {
	case "tcp4":
		ipv4 = true
	case "tcp6":
		ipv4 = false
	default:
		return fmt.Errorf("bgp: cannot set socket options on network %q", network)
	}

	if o.GTSM {
		if err := setGTSM(c, ipv4); err != nil {
			return err
		}
	}

	if o.DSCP != 0 {
		if err := setDSCP(c, ipv4, o.DSCP); err != nil {
			return err
		}
	}

	if o.UserTimeout != 0 {
		if err := setUserTimeout(c, o.UserTimeout); err != nil {
			return err
		}
	}

	if o.SendBuffer != 0 {
		if err := setBuffer(c, true, o.SendBuffer); err != nil {
			return err
		}
	}

	if o.RecvBuffer != 0 {
		if err := setBuffer(c, false, o.RecvBuffer); err != nil {
			return err
		}
	}

	return nil
}

// A Dialer creates BGP connections by performing an active open. It applies
// the TCP socket options a BGP speaker typically needs. The zero value is
// usable and produces a plain TCP connection.
type Dialer struct {
	// TCPOptions are the socket options applied to each dialed connection.
	TCPOptions

	// LocalAddr optionally binds the local side of the connection to a
	// specific address, port, or both. The zero value binds nothing, the
	// normal posture for an active open: BGP speakers connect from an
	// ephemeral port.
	LocalAddr netip.AddrPort

	// Port is the TCP port the peer is dialed on. The zero value is Port,
	// the well-known 179.
	Port uint16
}

// Dial performs an active open to the BGP speaker at addr, on the Dialer's
// Port, and returns a Conn over the resulting connection.
func (d *Dialer) Dial(ctx context.Context, addr netip.Addr) (*Conn, error) {
	return d.dial(ctx, addr, "")
}

// dial implements Dial, optionally authenticating the connection with a
// TCP-MD5 key: the peering's key from PeerConfig.MD5Password on the Peer's
// active open path. An empty md5 disables TCP-MD5.
func (d *Dialer) dial(ctx context.Context, addr netip.Addr, md5 string) (*Conn, error) {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return nil, fmt.Errorf("bgp: invalid remote address: %s", addr)
	}

	port := d.Port
	if port == 0 {
		port = Port
	}

	raddr := netip.AddrPortFrom(addr, port)
	if err := d.check(); err != nil {
		return nil, err
	}

	nd := &net.Dialer{
		Control: func(network string, _ string, c syscall.RawConn) error {
			if md5 != "" {
				if err := setMD5(c, addr, md5); err != nil {
					return err
				}
			}

			return d.control(network, c)
		},
	}

	nd.SetMultipathTCP(useMultipathTCP)
	d.keepAlive(&nd.KeepAlive, &nd.KeepAliveConfig)
	if d.LocalAddr != (netip.AddrPort{}) {
		nd.LocalAddr = net.TCPAddrFromAddrPort(d.LocalAddr)
	}

	c, err := nd.DialContext(ctx, tcpNetwork(addr), raddr.String())
	if err != nil {
		return nil, err
	}

	if err := setNoDelay(c); err != nil {
		_ = c.Close()
		return nil, err
	}

	return NewConn(c), nil
}

// A ListenConfig contains options for a Listener. The zero value is usable
// and produces a plain TCP listener.
type ListenConfig struct {
	// TCPOptions are the socket options applied to the listening socket,
	// which every accepted connection inherits.
	TCPOptions
}

// Listen begins listening for BGP connections on laddr, which must carry a
// valid address. A Listener is always bound to exactly one address family,
// so that socket options such as GTSM apply to every connection it accepts.
// To listen on every address of one family, use 0.0.0.0 or ::. A port of
// zero selects an ephemeral port, which Listener.Addr reports.
func (lc *ListenConfig) Listen(ctx context.Context, laddr netip.AddrPort) (*Listener, error) {
	addr := laddr.Addr().Unmap()
	if !addr.IsValid() {
		return nil, fmt.Errorf("bgp: listen address must carry an IPv4 or IPv6 address: %s", laddr)
	}

	laddr = netip.AddrPortFrom(addr, laddr.Port())
	if err := lc.check(); err != nil {
		return nil, err
	}

	nlc := &net.ListenConfig{
		Control: func(network string, _ string, c syscall.RawConn) error {
			return lc.control(network, c)
		},
	}

	nlc.SetMultipathTCP(useMultipathTCP)
	lc.keepAlive(&nlc.KeepAlive, &nlc.KeepAliveConfig)

	l, err := nlc.Listen(ctx, tcpNetwork(addr), laddr.String())
	if err != nil {
		return nil, err
	}

	tl, ok := l.(*net.TCPListener)
	if !ok {
		_ = l.Close()
		return nil, fmt.Errorf("bgp: unexpected listener type %T", l)
	}

	rc, err := tl.SyscallConn()
	if err != nil {
		_ = tl.Close()
		return nil, err
	}

	return &Listener{l: tl, rc: rc, v4: addr.Is4()}, nil
}

// A Listener accepts BGP connections opened by a peer: the passive open.
type Listener struct {
	l *net.TCPListener

	// v4 records the single address family the socket is bound to, which
	// scopes a Server's key installation; see serves.
	v4 bool

	// rc is the listening socket itself, on which TCP-MD5 keys are installed:
	// the kernel requires a key to be present before a peer's SYN arrives, and
	// accepted connections inherit the listening socket's keys.
	rc syscall.RawConn
}

// Accept waits for and returns the next connection to the Listener, mirroring
// the net.Listener method of the same name. Close unblocks a pending Accept.
func (l *Listener) Accept() (*Conn, error) {
	for {
		c, err := l.l.AcceptTCP()
		if err != nil {
			return nil, err
		}

		if err := setNoDelay(c); err != nil {
			// A connection which cannot take socket options is already
			// dead. Its failure belongs to the connection, not the
			// listener, so it must not surface as an Accept error: close
			// it and accept the next.
			_ = c.Close()
			continue
		}

		return NewConn(c), nil
	}
}

// SetMD5 installs a TCP-MD5 (RFC 2385) key for the speaker at peer on the
// listening socket, authenticating the connections accepted from peer. The
// password must not be empty, and installing a key for a peer which already has
// one replaces it. The key must be installed before the peer's SYN arrives.
//
// SetMD5 covers accepted connections only. On the Peer path, set
// PeerConfig.MD5Password instead: it signs the peer's dialed connections, and a
// Server installs it on its listeners via this method.
//
// TCP-MD5 is only supported on Linux. Elsewhere, SetMD5 returns an error which
// wraps [errors.ErrUnsupported].
func (l *Listener) SetMD5(peer netip.Addr, password string) error {
	if password == "" {
		return errors.New("bgp: a TCP-MD5 password is required; RemoveMD5 removes a key")
	}

	peer = peer.Unmap()
	if !peer.IsValid() {
		return fmt.Errorf("bgp: invalid peer address: %s", peer)
	}

	return setMD5(l.rc, peer, password)
}

// RemoveMD5 removes the TCP-MD5 key installed for peer by SetMD5, restoring
// plain TCP for the speaker at peer. Removing a key which was never installed
// is not an error.
//
// RemoveMD5 is only supported on Linux, and elsewhere returns an error which
// wraps [errors.ErrUnsupported].
func (l *Listener) RemoveMD5(peer netip.Addr) error {
	peer = peer.Unmap()
	if !peer.IsValid() {
		return fmt.Errorf("bgp: invalid peer address: %s", peer)
	}

	// The kernel removes a key by installing a zero length one.
	return setMD5(l.rc, peer, "")
}

// serves reports whether the Listener is bound to peer's address family:
// IPv4 and IPv6 alike, a peer's key belongs on exactly the listeners its
// SYN could reach.
func (l *Listener) serves(peer netip.Addr) bool { return l.v4 == peer.Is4() }

// Addr returns the Listener's network address.
func (l *Listener) Addr() net.Addr { return l.l.Addr() }

// Close closes the Listener, unblocking any pending Accept. Connections
// already returned by Accept are unaffected.
func (l *Listener) Close() error { return l.l.Close() }

// tcpNetwork returns the single-family network name for addr, which must be
// valid. The IPv6 network "tcp6" never produces a dual-stack socket: the net
// package binds it v6-only.
func tcpNetwork(addr netip.Addr) string {
	if addr.Is4() {
		return "tcp4"
	}

	return "tcp6"
}

// setNoDelay disables Nagle's algorithm on c. BGP is a control protocol where
// a delayed KEEPALIVE or NOTIFICATION costs far more than a small packet;
// message batching, when it is wanted, belongs in the write path instead.
func setNoDelay(c net.Conn) error {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("bgp: unexpected connection type %T", c)
	}

	return tc.SetNoDelay(true)
}
