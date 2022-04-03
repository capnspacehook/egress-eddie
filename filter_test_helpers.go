package main

import (
	"os/exec"
	"testing"

	"github.com/anmitsu/go-shlex"
)

func iptablesCmd(t *testing.T, args string) {
	splitArgs, err := shlex.Split(args, true)
	if err != nil {
		t.Fatalf("error spitting command %v: %v", args, err)
	}

	if err := exec.Command("iptables", splitArgs...).Run(); err != nil {
		t.Fatalf("error running command %v: %v", args, err)
	}
}
