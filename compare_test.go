package main

import (
	"testing"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/google/go-cmp/cmp"
)

// Sample LinuxSecompActions
var defAction specs.LinuxSeccompAction = "defAction"
var otherAction specs.LinuxSeccompAction = "otherAction"

// Sample seccomp rules
var dfltRule = specs.LinuxSyscall { Names: []string{"exit", "getuid"}, Action: defAction}

var stricter1Rule = specs.LinuxSyscall { Names: []string{"exit"}, Action: defAction}
var stricter2Rule = specs.LinuxSyscall { Names: []string{"getuid"}, Action: defAction}

var identicalRule = specs.LinuxSyscall { Names: []string{"exit", "getuid"}, Action: defAction}

var otherRule1 = specs.LinuxSyscall { Names: []string{"exit", "getuid"}, Action: otherAction}
var otherRule2 = specs.LinuxSyscall { Names: []string{"getuid"}, Action: otherAction}
var otherRule3 = specs.LinuxSyscall { Names: []string{"exit"}}

var diffSyscalls1Rule = specs.LinuxSyscall { Names: []string{"read", "write"}, Action: defAction}
var diffSyscalls2Rule = specs.LinuxSyscall { Names: []string{"exit", "getuid", "read"}, Action: defAction}

// Sample seccomp profiles
var dflt = specs.LinuxSeccomp {
	Syscalls: []specs.LinuxSyscall{dfltRule},
}

var stricter1 = specs.LinuxSeccomp {
	Syscalls: []specs.LinuxSyscall{stricter1Rule},
}

var stricter2 = specs.LinuxSeccomp {
	Syscalls: []specs.LinuxSyscall{stricter2Rule},
}

var identical = specs.LinuxSeccomp {
	Syscalls: []specs.LinuxSyscall{identicalRule},
}

var diffRule1 = specs.LinuxSeccomp {
	Syscalls: []specs.LinuxSyscall{otherRule1},
}

var diffRule2 = specs.LinuxSeccomp {
	Syscalls: []specs.LinuxSyscall{otherRule2},
}

var diffRule3 = specs.LinuxSeccomp {
	Syscalls: []specs.LinuxSyscall{otherRule3},
}

var diffSyscalls1 = specs.LinuxSeccomp {
	Syscalls: []specs.LinuxSyscall{diffSyscalls1Rule},
}

var diffSyscalls2 = specs.LinuxSeccomp {
	Syscalls: []specs.LinuxSyscall{diffSyscalls2Rule},
}

var multiRuleIdentical = specs.LinuxSeccomp {
	Syscalls: []specs.LinuxSyscall{stricter1Rule, stricter2Rule},
}

var multiRuleDifferent = specs.LinuxSeccomp {
	Syscalls: []specs.LinuxSyscall{stricter1Rule, otherRule2},
}

// Tests
func TestCompareIdentical(t *testing.T) {
	if !cmp.Equal(compare(dflt, identical), dflt) {
		t.Errorf("Error: comparison with identical should return default")
	}
}

func TestCompareStricter1(t *testing.T) {
	if !cmp.Equal(compare(dflt, stricter1), stricter1) {
		t.Errorf("Error: profile stricter1 should be more strict than default")
	}
}

func TestCompareStricter2(t *testing.T) {
	if !cmp.Equal(compare(dflt, stricter2), stricter2) {
		t.Errorf("Error: profile stricter2 should be more strict than default")
	}
}

func TestCompareDiffRule1(t *testing.T) {
	if !cmp.Equal(compare(dflt, diffRule1), dflt) {
		t.Errorf("Error: profile diffrule1 should be less strict than default")
	}
}

func TestCompareDiffRule2(t *testing.T) {
	if !cmp.Equal(compare(dflt, diffRule2), dflt) {
		t.Errorf("Error: profile diffrule2 should be less strict than default")
	}
}

func TestCompareDiffRule3(t *testing.T) {
	if !cmp.Equal(compare(dflt, diffRule3), dflt) {
		t.Errorf("Error: profile diffrule3 should be less strict than default")
	}
}

func TestCompareDiffSyscalls1(t *testing.T) {
	if !cmp.Equal(compare(dflt, diffSyscalls1), dflt) {
		t.Errorf("Error: profile diffsyscalls1 should be less strict than default")
	}
}

func TestCompareDiffSyscalls2(t *testing.T) {
	if !cmp.Equal(compare(dflt, diffSyscalls2), dflt) {
		t.Errorf("Error: profile diffsyscalls2 should be less strict than default")
	}
}

func TestCompareMultiRuleIdentical(t *testing.T) {
	if !cmp.Equal(compare(dflt, multiRuleIdentical), dflt) {
		t.Errorf("Error: comparison with identical should return default")
	}
}

func TestCompareMultiRuleDifferent(t *testing.T) {
	if !cmp.Equal(compare(dflt, multiRuleDifferent), dflt) {
		t.Errorf("Error: comparison with multiruledifferent should return default")
	}
}
