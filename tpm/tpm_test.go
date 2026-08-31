package tpm_test

import (
	"go-tpm2/tpm"
	"testing"
)

func TestParseReturnCode(t *testing.T) {
	returncode := 0x000009A2
	target := tpm.RCBadAuth

	parsed := tpm.ParseReturnCode(uint32(returncode))

	if parsed.Get() != target.Get() {
		t.Fatalf("Failed on parsing, %x is not %x\n", parsed.Get(), target.Get())
	}
}
