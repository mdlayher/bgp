//go:build interop && !linux

package interop

import (
	"log"
	"testing"
)

func TestMain(_ *testing.M) {
	// A hard failure, never a skip — and never a green zero-test run:
	// the FRR oracle runs in nested network namespaces, which need
	// Linux. See the package documentation in harness.go.
	log.Fatal("interop: this suite requires Linux to host the FRR oracle in network namespaces")
}
