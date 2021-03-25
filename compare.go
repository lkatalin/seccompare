package main

import (
        "fmt"
        specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/google/go-cmp/cmp"
)

// Returns true if syscall is in the given slice of syscalls, else returns false.
func contains(slice []specs.LinuxSyscall, syscall specs.LinuxSyscall) bool {
	for _, elm := range slice {
		if cmp.Equal(elm, syscall) {
			return true
		}
	}

	return false
}

// This function compares the seccomp profile of an image against a default
// seccomp profile and returns the image profile iff it is a strict subset of
// the default profile.
// TODO: Always compare against a const default profile instead of any profile?
func compare(img specs.LinuxSeccomp, dflt specs.LinuxSeccomp) specs.LinuxSeccomp {
	// TODO: This is redundant but can cut down on search time. Keep or delete?
	// If image profile has more syscalls than default, it will not
	// be a subset.
	if len(img.Syscalls) >= len(dflt.Syscalls) {
		return dflt
	}

	// If any syscall in image profile is not in default profile, it will
	// not be a subset.
	for _, element := range img.Syscalls {
		if !contains(dflt.Syscalls, element) {
			return dflt
		}
	}

	return img
}

func main() {
	fmt.Println("use go test to try comparing sample seccomp profiles")
}
