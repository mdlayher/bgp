//go:build interop && linux

package interop

import (
	"log"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// The binary wears three hats: the process go test starts
	// re-executes itself into a user+network namespace, each instance
	// start re-executes it again as a tiny init, and only
	// the namespaced child runs tests. See netns.go.
	switch {
	case os.Getenv(envNSInit) != "":
		nsInit() // never returns
	case os.Getenv(envNSChild) != "":
		rt = newNSRuntime()
		os.Exit(m.Run())
	}

	// The original invocation: find the oracle, then enter the
	// namespaces. No oracle is a hard failure, never a skip: see the
	// package documentation.
	if os.Getenv(envFRR) == "" {
		dir := detectFRR()
		if dir == "" {
			log.Fatalf("interop: no FRR daemons found for the oracle; install FRR %s (the repository's nix dev shell provides it) or set $%s",
				frrVersion, envFRR)
		}
		os.Setenv(envFRR, dir)
	}

	// Re-enters TestMain as the namespaced child above.
	os.Exit(nsReexec())
}
