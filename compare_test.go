package main

import (
	"testing"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/google/go-cmp/cmp"
)

// Sample syscalls
var read = specs.LinuxSyscall { Names: []string{"read"} }
var write = specs.LinuxSyscall {  Names: []string{"write"} }
var _ = specs.LinuxSyscall { Names: []string{"exit"} }
var _ = specs.LinuxSyscall { Names: []string{"getuid"} }
var uname = specs.LinuxSyscall { Names: []string{"uname"} }
var pipe = specs.LinuxSyscall { Names: []string{"pipe"} }
var mmap = specs.LinuxSyscall { Names: []string{"mmap"} }
var getpid = specs.LinuxSyscall { Names: []string{"getpid"} }
var brk = specs.LinuxSyscall { Names: []string{"brk"} }
var getrandom = specs.LinuxSyscall { Names: []string{"getrandom"} }

// Sample syscall slices
var sysvecDefault = []specs.LinuxSyscall {pipe, mmap, getpid, brk, getrandom}
var sysvecLessStrict1 = []specs.LinuxSyscall {read, write} // read, write ∉ default set
var sysvecLessStrict2 = []specs.LinuxSyscall {pipe, mmap, getpid, brk, getrandom, uname} // uname ∉ default set
var sysvecMoreStrict = []specs.LinuxSyscall {pipe, mmap} // ⊂ default set 
var sysvecSame = []specs.LinuxSyscall {pipe, mmap, getpid, brk, getrandom} // ⊆ default set

// Sample seccomp profiles
var seccompDefault = specs.LinuxSeccomp {
	Syscalls: sysvecDefault,
}

var seccompLessStrict1 = specs.LinuxSeccomp {
	Syscalls: sysvecLessStrict1,
}

var seccompLessStrict2 = specs.LinuxSeccomp {
	Syscalls: sysvecLessStrict2,
}

var seccompMoreStrict = specs.LinuxSeccomp {
	Syscalls: sysvecMoreStrict,
}

var seccompSame = specs.LinuxSeccomp {
	Syscalls: sysvecSame,
}

func TestContains(t *testing.T) {
	if contains(sysvecDefault, read) {
		t.Errorf("Error: sysvecDefault should not contain read call")
	}

	if !contains(sysvecDefault, pipe) {
		t.Errorf("Error: sysvecDefault should contain pipe call")
	}
}

func TestCompare(t *testing.T) {
	if !cmp.Equal(compare(seccompLessStrict1, seccompDefault), seccompDefault) {
		t.Errorf("Error: seccompLessStrict1 should be less strict than default")
	}

	if !cmp.Equal(compare(seccompLessStrict2, seccompDefault), seccompDefault) {
		t.Errorf("Error: seccompLessStrict2 should be less strict than default")
	}

	if !cmp.Equal(compare(seccompMoreStrict, seccompDefault), seccompMoreStrict) {
		t.Errorf("Error: seccompMoreStrict should be more strict than default")
	}

	if !cmp.Equal(compare(seccompSame, seccompDefault), seccompDefault) {
		t.Errorf("Error: profiles are the same, so Default should be returned")
	}
}
