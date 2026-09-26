# CLAUDE.md

Guidance for AI agents working in this repository.

## Verification

Run these on every Go change, alongside `go build` and `go test`:

- `gofumpt -l .` (CI enforces gofumpt; keep stderr visible so a bad path
  can't look like a clean run)
- `go vet ./...`
- `staticcheck ./...` (CI enforces it; if the system binary is too old for
  the toolchain, use `go run honnef.co/go/tools/cmd/staticcheck@latest ./...`)
- `gopls check -severity=hint <changed files>` (catches unusedfunc,
  modernize, typeargs, and other hint-level findings vet and staticcheck
  miss)

`./...` from the repository root covers only the root module. If the
repository contains nested Go modules, run the checks inside each changed
module too.

## Code style

Blank lines:

- Leave an empty line after a closing brace and after a `var (` / `const (`
  block when another statement or declaration follows at the same indent
  level. Keep `}`, `)`, `case`, `default:`, and `else` continuations tight
  against what precedes them.
- Break dense bodies, especially tests, with blank lines at logical seams:
  between multi-line handler fields in a config struct literal, between one
  actor's cluster of steps and the next, before non-blocking `select`
  assertion checks and final verdict assertions, and between constructing a
  fixture and the next setup statement.
- A single multi-line struct literal is one logical unit: never split it
  mid-literal.
- A struct literal setting more than one field is written across multiple
  lines, one field per line, however short it is. Several fields on one
  line do not read: the names and the values run together, and gofmt
  aligns nothing it can keep on a single line. A literal setting one field
  stays inline. Where that would expand a literal in the middle of a call
  or a condition, name the value on the line above instead, which is the
  case for a name used once that the inlining rule allows.

Declaration layout:

- A type and all of its methods stay contiguous. Supporting enums and codes
  go before the type that uses them. Constructor/decoder pairs sit together
  (e.g. `MultiprotocolCapability` beside `Capability.Multiprotocol`).
- Paired values described by one doc comment share one declaration
  (`PeerASN, LocalASN uint32`). A doc comment attaches to the declaration,
  so separate lines leave every name after the first undocumented in go doc
  and IDE hover.
- Exception: files deliberately organized by theme or flow keep that layout
  (e.g. `bgp_clone.go` as a file of Clone methods; `attempt.go`,
  `fsmconn.go`, and `negotiate.go` in FSM flow order).
- Keep groups of one-line method stubs compact and aligned, with no blank
  lines between them.

Expressions:

- Use `errors.AsType[*T](err)`, never `errors.As` with a pointer to a
  target variable.
- Inline a value used once instead of naming it: pass the composite
  literal or call at its one use rather than binding it to a variable
  first. A name earns its line when it is used twice, breaks a line that
  would not otherwise fit, or explains a magic value.
- Do not name what is already named. A local whose initializer is a field,
  a parameter, or another variable in scope, and a field whose value is
  one another field already reaches, are each a second name for one value
  and a place for the two to drift; reach through the original at every
  use. The exception is a value read under a lock and used after it is
  released, where the local is the copy which makes that safe.

Signatures:

- A function with more than three parameters takes a struct instead, and
  one with more than three results returns a struct. A `context.Context`
  counts as a parameter; keep it first and put the rest in the struct.
  Long positional lists are easy to misorder at the call site, and a struct
  names each value, lets callers omit defaults, and grows without breaking
  callers.

Goroutines:

- Every goroutine's lifetime is tracked by the value which started it,
  with a `sync.WaitGroup`, an `errgroup.Group`, or the equivalent. Prefer
  `wg.Go(f)` to `Add`, `go`, and `Done`, which gopls asks for anyway. A
  goroutine nothing waits on outlives its owner, and whatever it writes
  to, a socket, a log, a test's output, has been taken away by then.
- A goroutine which blocks obeys the context it was started with, so
  cancellation is what stops it and the wait which follows is bounded.
- A type which starts goroutines has a Close, and Close returns only once
  every one of them has returned. Start the goroutine under the same lock
  Close takes to refuse new ones, so a start can never race the wait.
- A test joins whatever it started, and whatever the value under test
  started, before it returns. A late write is a goroutine outliving its
  test, which is the bug; silencing the write hides it.

Locks:

- A type's lock, and the state it guards, are that type's own. Never lock
  another type's mutex or touch what it protects, not even from inside the
  same package, where the compiler allows it. Reaching for another type's
  lock is the symptom; the cause is a missing method on the type which
  owns it. Add that method, put the locking inside it, and call it. The
  owner is then the one place the invariant is written down and the one
  place to look when it breaks.
- A method which requires its type's lock to be held already is suffixed
  `Locked`, such as `observeLocked`, and says so in its doc comment as
  well. The suffix puts the requirement at every call site instead of only
  at the declaration, so a new caller reaching for one from outside the
  lock sees it while writing the call. A method which takes the lock
  itself carries no suffix: the name describes what the caller must have
  done, not what the method does.
- A lock is held for a decision, not for the work which follows it. Do the
  reading and the writing it guards, release it, and only then call a
  caller's callback or touch a socket: a callback under a lock is a
  deadlock waiting for that callback to reach back in, and a socket under
  one blocks every other holder for as long as the far end is slow. The
  exception is work the lock exists to serialize, which says as much where
  it happens.

Logging:

- A log call on a per-message path is guarded by
  `if f.log.Enabled(ctx, slog.LevelDebug)`. `slog` checks the level inside
  the call, after Go has evaluated the arguments and boxed each one into
  an `any`, so a disabled Debug still pays for every argument it was
  given. Two allocations per UPDATE are invisible in steady state and very
  visible during a full-table convergence burst. The guard belongs on the
  read loop, the writer loop, and anything else which runs per message. It
  is noise anywhere else, so per-connection and per-transition logs go
  unguarded.
- What the boxing costs depends on the value. A pointer, an `error`, a
  string already in hand, and a small integer type such as `origin` box
  for free. A large `int`, a multi-word struct, and a string built at the
  call site by `String` or `Sprintf` each allocate. An argument of the
  second kind on a hot path is the one which has to be guarded.

Code comments:

- State the contract directly, and the reasoning once: a doc comment says
  what a thing does, an inline comment what is surprising at that line,
  and a test's doc what it proves.
- Exported doc comments are self-contained: no references to design
  documents that live outside this repository. When a comment needs a
  decision's rationale, carry the one-sentence version inline.
- Plain prose: short sentences, no em dashes. Prefer separate sentences, a
  colon, or "such as X or Y" over parenthetical asides.

Markdown documents:

- Wrap prose at 80 columns for terminal splits. Table rows are exempt: they
  cannot wrap.

## Tests

- Never sleep in tests. Every awaited condition must be signaled; poll
  loops with sleep intervals count as sleeping.
- `t.Parallel()` is the first statement of every Test function and of
  every subtest, followed by a blank line. A test which cannot be
  parallel says why in a comment above the missing call. The rule is not
  for speed, which is already dominated by process startup: it is a
  standing assertion that each test owns everything it touches, and it
  makes the race detector interleave tests rather than run them in a
  fixed order.
- What that rule demands of a test: bind port 0 and read the port back
  rather than picking a number, give each test its own listener, server,
  and peer, and never reach for process-wide state. `t.Setenv` and
  `t.Chdir` are process-wide and panic in a parallel test, so a test
  needing either is one of the exceptions and says so.
- Tear a shared fixture down with `t.Cleanup`, never `defer`. A parent's
  `defer` runs when its body returns, which is before its parallel
  subtests run; its `t.Cleanup` runs after the last of them finishes,
  which is the only ordering that keeps a fixture alive for the cases
  using it.
- Independent scenarios are individual top-level Test functions. `t.Run`
  is for a table's cases and for subtests sharing a fixture built by the
  parent, such as one Test with per-case setup on a shared listener.
- Test scenarios, not coverage. Cover paths a plausible real-world scenario
  hits, framed on behavior; 100% coverage is not a goal.
- Compare a complex type with the `diff` helper in `bgp_test.go`, never
  field by field or with `slices.Equal`: slices, maps, and structs all go
  through it, and the failure prints the difference rather than the two
  whole values for a reader to spot it in. Scalars keep `!=`. The
  exception is a type cmp cannot walk, a struct whose fields are all
  unexported, which needs a comparison and a comment saying why; a type
  with one unexported field beside exported ones is taught to `diff`
  instead.
- Test helpers, rig types, and shared fixtures go at the end of test files,
  after every Test/Fuzz/Benchmark/Example function. Shared consts may stay
  at the top. A rig shared by several test files lives in a file named for
  it, such as `peer_rig_test.go`, with no Test functions of its own.
- No real peer names, interfaces, or peer ASNs in test fixtures: name
  peers neutrally, such as `dn42e-0` with a private ASN like 64512. Matt's
  own dn42 ASN, 4242423610, and his ranges are fine to use.

## This repository

- Module `github.com/mdlayher/bgp`, a BGP library: the wire format, the
  FSM, and the Peer and Server which drive it. It has no daemon; callers
  own routing state and policy.
- Tests and the gate always run with `-race`: `go test -race ./...`.
- No package-level mutable state. A package-level value is immutable and
  says so, such as `implicitFamilies`.
- Commit messages are `component: description` with a `Signed-off-by`
  trailer and no other trailer. Agents never commit or push; Matt signs
  every commit.
- MIT (LICENSE.md).
