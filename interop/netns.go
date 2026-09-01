//go:build interop && linux

package interop

// The netns runtime hosts the FRR oracle: its daemons run in a nested
// network namespace joined to the test's own namespace by a veth pair,
// and everything works with unprivileged user namespaces — no root
// required.
//
// The test binary wears three hats, told apart by environment markers
// in TestMain:
//
//  1. The process go test starts: nsReexec immediately re-executes it
//     into a new user namespace (mapping the user to root) plus a
//     fresh network namespace for the harness network.
//  2. The namespaced child: actually runs the tests. Each startFRR
//     spawns hat three and speaks a two-line pipe protocol with it to
//     hand over the veth peer.
//  3. A per-instance init (nsInit): holds the oracle's fresh
//     net+uts+mount namespaces — the kernel hostname pin, tmpfs over
//     FRR's compiled-in state paths — and supervises the daemons,
//     which die with it via parent-death signals.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	stdruntime "runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Environment variables wiring the runtime. envFRR is the daemon
// directory — set by the user, or by TestMain from detectFRR; the rest
// are internal plumbing for the re-executions described above.
const (
	envFRR     = "BGP_INTEROP_FRR"
	envNSChild = "BGP_INTEROP_NETNS_CHILD"
	envNSInit  = "BGP_INTEROP_NETNS_INIT"
	envNSRun   = "BGP_INTEROP_NETNS_RUN"
)

// The veth endpoint names: the host side stays in the test's namespace
// carrying the gateway addresses, while the FRR side moves into the
// instance's namespace. Instances are serial, so fixed names serve
// every scenario; instance teardown removes the pair.
const (
	vethHost = "bgpi-host"
	vethFRR  = "bgpi-frr"
)

// rt hosts the suite's FRR instances, set once by TestMain in the
// namespaced child for the life of the test binary.
var rt *nsRuntime

// detectFRR locates the FRR daemons when $BGP_INTEROP_FRR does not
// name them, returning "" when none are found. Distro packages install
// the daemons off $PATH in a libexec-style directory, and vtysh —
// which does land on $PATH — signposts a relocated install (Nix, the
// dev shell, /usr/local) from its prefix.
func detectFRR() string {
	candidates := []string{"/usr/lib/frr", "/usr/libexec/frr"}
	if vtysh, err := exec.LookPath("vtysh"); err == nil {
		if vtysh, err = filepath.EvalSymlinks(vtysh); err == nil {
			prefix := filepath.Dir(filepath.Dir(vtysh))
			candidates = append(
				candidates,
				filepath.Join(prefix, "libexec", "frr"),
				filepath.Join(prefix, "lib", "frr"),
			)
		}
	}

	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "zebra")); err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "bgpd")); err == nil {
			return dir
		}
	}

	return ""
}

// nsReexec is hat one: re-execute the test binary inside a fresh
// user+network namespace and relay its verdict.
func nsReexec() int {
	cmd := exec.Command("/proc/self/exe", os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), envNSChild+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		// Root inside the namespace is this user outside: enough to
		// create veth pairs and nested namespaces, and nothing more.
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}

	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	default:
		log.Printf("interop: failed to re-execute into a user namespace: %v", err)
		return 1
	}
}

// An nsRuntime hosts FRR instances as daemons in nested namespaces.
type nsRuntime struct {
	daemons string // the $BGP_INTEROP_FRR daemon directory
	vtysh   string // the resolved vtysh binary
}

// newNSRuntime validates $BGP_INTEROP_FRR inside the namespaced child.
// Failures are fatal to the process, never a skip: see the package
// documentation.
func newNSRuntime() *nsRuntime {
	dir := os.Getenv(envFRR)
	for _, d := range []string{"zebra", "bgpd"} {
		if _, err := os.Stat(filepath.Join(dir, d)); err != nil {
			log.Fatalf("interop: $%s does not provide %s: %v", envFRR, d, err)
		}
	}

	// vtysh commonly lives apart from the daemons: alongside them, in
	// the install's own bin (../../bin from e.g. libexec/frr), or on
	// $PATH (/usr/bin for distro packages).
	var vtysh string
	for _, c := range []string{
		filepath.Join(dir, "vtysh"),
		filepath.Join(dir, "..", "..", "bin", "vtysh"),
	} {
		if _, err := os.Stat(c); err == nil {
			vtysh = c
			break
		}
	}
	if vtysh == "" {
		v, err := exec.LookPath("vtysh")
		if err != nil {
			log.Fatalf("interop: vtysh not found near $%s or on $PATH: %v", envFRR, err)
		}
		vtysh = v
	}

	// The frrVersion tripwire: oracle drift must be a loud failure,
	// never a quiet swap.
	out, err := exec.Command(filepath.Join(dir, "bgpd"), "--version").Output()
	if err != nil {
		log.Fatalf("interop: failed to run bgpd --version: %v", err)
	}
	first, _, _ := strings.Cut(string(out), "\n")
	if f := strings.Fields(first); len(f) < 3 || f[2] != frrVersion {
		log.Fatalf("interop: the oracle must be FRR %s, but bgpd reports: %s", frrVersion, first)
	}

	// The re-exec landed in an empty network namespace; even
	// loopback starts down.
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		log.Fatalf("interop: failed to bring up loopback: %v: %s", err, out)
	}

	return &nsRuntime{daemons: dir, vtysh: vtysh}
}

// startFRR starts one FRR oracle instance running the rendered
// configuration conf by spawning an nsInit and wiring the veth pair to
// it, registering teardown (including log capture) on t. It returns as
// soon as the daemons exist; callers poll the handle for bgpd actually
// answering.
func (n *nsRuntime) startFRR(t *testing.T, name string, conf []byte) *nsFRR {
	t.Helper()

	// The vty sockets need a short directory: sun_path caps unix
	// socket paths at 108 bytes, which the nested directories of
	// t.TempDir can exceed.
	run, err := os.MkdirTemp("/tmp", "bgp-interop")
	if err != nil {
		t.Fatalf("failed to create instance directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(run) })

	// The instance's config directory: the rendered config plus
	// vtysh.conf, whose presence keeps vtysh from polluting command
	// output with a missing-file complaint.
	etc := t.TempDir()
	vtyshConf, err := os.ReadFile(filepath.Join("testdata", "frr", "vtysh.conf"))
	if err != nil {
		t.Fatalf("failed to read vtysh.conf: %v", err)
	}
	for file, b := range map[string][]byte{"frr.conf": conf, "vtysh.conf": vtyshConf} {
		if err := os.WriteFile(filepath.Join(etc, file), b, 0o644); err != nil {
			t.Fatalf("failed to write %s: %v", file, err)
		}
	}

	// The group file nsInit bind-mounts over /etc/group: zebra's
	// privs_init insists on resolving the compiled-in frrvty group,
	// which we alias to gid 0, the only gid mapped in this user
	// namespace.
	group, err := os.ReadFile("/etc/group")
	if err != nil {
		t.Fatalf("failed to read /etc/group: %v", err)
	}
	if err := os.WriteFile(filepath.Join(run, "group"), append(group, "frrvty:x:0:\n"...), 0o644); err != nil {
		t.Fatalf("failed to write group file: %v", err)
	}

	init := exec.Command("/proc/self/exe")
	init.Env = append(os.Environ(), envNSInit+"=1", envNSRun+"="+run)
	init.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWUTS | syscall.CLONE_NEWNS,
	}

	stdin, err := init.StdinPipe()
	if err != nil {
		t.Fatalf("failed to open init stdin: %v", err)
	}
	stdout, err := init.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to open init stdout: %v", err)
	}
	initLog, err := os.Create(filepath.Join(run, "init.log"))
	if err != nil {
		t.Fatalf("failed to create init log: %v", err)
	}
	init.Stderr = initLog

	if err := init.Start(); err != nil {
		t.Fatalf("failed to start FRR init: %v", err)
	}
	t.Cleanup(func() {
		// Logs first, while the instance still runs.
		var logs bytes.Buffer
		for _, f := range []string{"zebra.log", "bgpd.log", "init.log"} {
			b, _ := os.ReadFile(filepath.Join(run, f))
			fmt.Fprintf(&logs, "=== %s ===\n%s", f, b)
		}
		saveLogs(t, name, logs.Bytes())

		// Closing stdin tells init to take the daemons down and
		// exit, dissolving the namespaces and with them the veth
		// pair; the timer and the explicit delete are backstops.
		stdin.Close()
		timer := time.AfterFunc(10*time.Second, func() { _ = init.Process.Kill() })
		_ = init.Wait()
		timer.Stop()
		_ = exec.Command("ip", "link", "del", vethHost).Run()
	})

	sc := bufio.NewScanner(stdout)
	expect := func(want string) {
		t.Helper()
		if !sc.Scan() {
			b, _ := os.ReadFile(filepath.Join(run, "init.log"))
			t.Fatalf("FRR init never reported %q: %s", want, b)
		}
		if got := sc.Text(); got != want {
			t.Fatalf("unexpected report from FRR init: got %q, want %q", got, want)
		}
	}
	ipCmd := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("failed to run ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}

	// The handoff: once init's namespaces exist, build the veth pair
	// here, push one end into them, and let init take it from there.
	expect("ready")
	plen4 := strconv.Itoa(netip.MustParsePrefix(netV4).Bits())
	plen6 := strconv.Itoa(netip.MustParsePrefix(netV6).Bits())
	ipCmd("link", "add", vethHost, "type", "veth", "peer", "name", vethFRR)
	ipCmd("addr", "add", hostV4+"/"+plen4, "dev", vethHost)
	ipCmd("-6", "addr", "add", hostV6+"/"+plen6, "dev", vethHost, "nodad")
	ipCmd("link", "set", vethHost, "up")
	ipCmd("link", "set", vethFRR, "netns", strconv.Itoa(init.Process.Pid))
	fmt.Fprintln(stdin, "veth")
	expect("up")

	// The config load below needs both daemons' vty sockets, which
	// they bind asynchronously after starting. Polling an external
	// process is the documented exception to the repo's no-sleep
	// rule: see frr.poll.
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, zerr := os.Stat(filepath.Join(run, "zebra.vty"))
		_, berr := os.Stat(filepath.Join(run, "bgpd.vty"))
		if zerr == nil && berr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s vty sockets", name)
		}
		time.Sleep(250 * time.Millisecond)
	}

	// Load the integrated configuration now that both daemons are
	// listening.
	if out, err := exec.Command(
		n.vtysh, "--vty_socket", run, "--config_dir", etc,
		"-f", filepath.Join(etc, "frr.conf"),
	).CombinedOutput(); err != nil {
		t.Fatalf("failed to load FRR config: %v: %s", err, out)
	}

	return &nsFRR{r: n, run: run, etc: etc}
}

// An nsFRR drives vtysh against one instance's sockets.
type nsFRR struct {
	r        *nsRuntime
	run, etc string
}

// vtysh invokes vtysh against the instance's vty sockets with each
// command as its own -c argument, returning stdout — joined by stderr
// only on failure. vtysh retains mode across -c arguments, so nested
// lines (configure terminal, then router bgp, then neighbor
// statements) work as they would interactively.
func (f *nsFRR) vtysh(cmds ...string) ([]byte, error) {
	args := []string{"--vty_socket", f.run, "--config_dir", f.etc}
	for _, cmd := range cmds {
		args = append(args, "-c", cmd)
	}

	out, err := exec.Command(f.r.vtysh, args...).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			out = append(out, exit.Stderr...)
		}
	}

	return out, err
}

// nsInit is hat three: a tiny init holding the namespaces of one FRR
// instance. It never returns.
func nsInit() {
	// The daemons' parent-death signals watch the thread that
	// spawned them; pinning the main goroutine keeps that thread
	// alive for the life of the process.
	stdruntime.LockOSThread()

	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "nsInit: "+format+"\n", args...)
		os.Exit(1)
	}

	run := os.Getenv(envNSRun)
	daemons := os.Getenv(envFRR)

	// Resolve iproute2 before the mounts below: masking /run breaks
	// $PATH lookups on distros (NixOS) whose entries resolve through
	// it.
	ipBin, err := exec.LookPath("ip")
	if err == nil {
		ipBin, err = filepath.EvalSymlinks(ipBin)
	}
	if err != nil {
		fail("iproute2 unavailable: %v", err)
	}
	ipCmd := func(args ...string) {
		if out, err := exec.Command(ipBin, args...).CombinedOutput(); err != nil {
			fail("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}

	// The instance environment: the pinned kernel hostname the FQDN
	// capability carries (see frrHostname), and private tmpfs over
	// /run and /var/lib so FRR's compiled-in state paths are
	// writable. The bind-mounted group file satisfies zebra's frrvty
	// lookup: see startFRR.
	if err := syscall.Sethostname([]byte(frrHostname)); err != nil {
		fail("sethostname: %v", err)
	}
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		fail("remounting / private: %v", err)
	}
	for _, dir := range []string{"/run", "/var/lib"} {
		if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
			fail("mounting tmpfs on %s: %v", dir, err)
		}
	}
	for _, dir := range []string{"/run/frr", "/var/lib/frr"} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fail("mkdir %s: %v", dir, err)
		}
	}
	if err := syscall.Mount(filepath.Join(run, "group"), "/etc/group", "", syscall.MS_BIND, ""); err != nil {
		fail("bind-mounting group file: %v", err)
	}

	ipCmd("link", "set", "lo", "up")

	// Hat two hands the veth peer over once we are visible.
	fmt.Println("ready")
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() || sc.Text() != "veth" {
		fail("did not receive the veth handoff: %q", sc.Text())
	}

	plen4 := strconv.Itoa(netip.MustParsePrefix(netV4).Bits())
	plen6 := strconv.Itoa(netip.MustParsePrefix(netV6).Bits())
	ipCmd("addr", "add", frrV4+"/"+plen4, "dev", vethFRR)
	ipCmd("-6", "addr", "add", frrV6+"/"+plen6, "dev", vethFRR, "nodad")
	ipCmd("link", "set", vethFRR, "up")

	daemon := func(name string, extra ...string) *exec.Cmd {
		logf, err := os.Create(filepath.Join(run, name+".log"))
		if err != nil {
			fail("creating %s log: %v", name, err)
		}

		cmd := exec.Command(filepath.Join(daemons, name), append(
			extra,
			"--vty_socket", run,
			"-i", "/run/frr/"+name+".pid",
			"-z", "/run/frr/zserv.api",
		)...)
		cmd.Stdout, cmd.Stderr = logf, logf
		// The backstop: the daemon dies with this process even if
		// the explicit kills below never run.
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if err := cmd.Start(); err != nil {
			fail("starting %s: %v", name, err)
		}

		return cmd
	}

	// Both daemons are required for the full suite: bgpd learns
	// interface addresses through zebra and cannot stand alone.
	// zebra has no --skip_runas; running as the namespace's root
	// sidesteps the missing frr user, with the group file covering
	// the rest. bgpd's -S skips the whole dance.
	zebra := daemon("zebra", "-u", "root", "-g", "root")
	bgpd := daemon("bgpd", "-S")

	fmt.Println("up")

	// Hold the namespaces until hat two closes our stdin, then take
	// the daemons down with us.
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = zebra.Process.Kill()
	_ = bgpd.Process.Kill()
	os.Exit(0)
}
