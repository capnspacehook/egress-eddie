//go:build test_binary

package main

import (
	"errors"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
)

var testingWithBinary = true

func initFilters(t *testing.T, configStr string, iptablesRules, ip6tablesRules []string) (*http.Client, *http.Client, func()) {
	f, err := os.CreateTemp("", "egress_eddie")
	if err != nil {
		t.Fatalf("error creating config file: %v", err)
	}
	configPath := f.Name()

	if _, err = f.Write([]byte(configStr)); err != nil {
		t.Fatalf("error writing config file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("error closing config file: %v", err)
	}

	iptablesCmd(t, false, "-F")
	for _, command := range iptablesRules {
		iptablesCmd(t, false, command)
	}

	iptablesCmd(t, true, "-F")
	for _, command := range ip6tablesRules {
		iptablesCmd(t, true, command)
	}

	eddieCmd := exec.Command("./eddie", "-c", configPath, "-d", "-f", "-l", "stdout")
	eddieCmd.Stdout = os.Stdout
	eddieCmd.Stderr = os.Stderr
	if err := eddieCmd.Start(); err != nil {
		t.Fatalf("error starting egress eddie binary: %v", err)
	}

	time.Sleep(time.Second)

	client4, client6 := getHTTPClients()

	stop := func() {
		eddieCmd.Process.Signal(os.Interrupt)

		if err := eddieCmd.Wait(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				t.Errorf("egress eddie exited with error: %v", err)
			}
		}
		os.Remove(configPath)

		iptablesCmd(t, false, "-F")
		iptablesCmd(t, true, "-F")
	}

	return client4, client6, stop
}
