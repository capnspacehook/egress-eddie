package main

import (
	"os/exec"
	"testing"

	"github.com/anmitsu/go-shlex"
)

func iptablesCmd(t *testing.T, ipv6 bool, args string) {
	splitArgs, err := shlex.Split(args, true)
	if err != nil {
		t.Fatalf("error spitting command %v: %v", args, err)
	}

	cmd := "iptables"
	if ipv6 {
		cmd = "ip6tables"
	}

	if err := exec.Command(cmd, splitArgs...).Run(); err != nil {
		t.Fatalf("error running command %v: %v", args, err)
	}
}
