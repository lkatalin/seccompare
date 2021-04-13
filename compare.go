package main

import (
        "fmt"
        specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/google/go-cmp/cmp"
)

// This function compares the seccomp profile of an image against a default
// seccomp profile and returns the image profile iff it is a strict subset of
// the default profile.
func compare(dflt specs.LinuxSeccomp, img specs.LinuxSeccomp) specs.LinuxSeccomp {
	// Create mapping of syscalls -> rules from both profiles.
	var defaultProfile = make(map[string]specs.LinuxSyscall)
	var imgProfile = make (map[string]specs.LinuxSyscall)
	for _, rule := range dflt.Syscalls {
		for _, name := range rule.Names {
			defaultProfile[name] = rule
		}
	}
	for _, rule := range img.Syscalls {
		for _, name := range rule.Names {
			imgProfile[name] = rule
		}
	}

	// Check whether set of syscalls in default is larger than the set in img;
	// if not, it won't be a strict subset, so return default.
	var allPresent = true
	for syscall := range defaultProfile {
		_, ok := imgProfile[syscall]
		if !ok {
			allPresent = false
		}
	}
	if allPresent {
		fmt.Println("img is not a subset; returning dflt")
		return dflt
	}

	// Check that all rules for img syscalls are the same ones present in the
	// default profile for that syscall.
	for syscall, imgRule := range imgProfile {
		defaultRule := defaultProfile[syscall]
		// TODO: better iterator over fields?
		if (!cmp.Equal(defaultRule.Action, imgRule.Action) ||
		    !cmp.Equal(defaultRule.ErrnoRet, imgRule.ErrnoRet) ||
		    !cmp.Equal(defaultRule.Args, imgRule.Args)) {
			fmt.Printf("default rule %v not equal to img rule %v for syscall %v; returning default\n", defaultRule.Action, imgRule.Action, syscall)
			return dflt
		}
	}

	fmt.Println("img is stricter; returning img")
	return img
}

func main() {
	fmt.Println("use go test to try comparing sample seccomp profiles")
}
