//go:build test_binary

package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
)

func initFilters(t *testing.T, configStr string, iptablesRules, ip6tablesRules []string) (*http.Client, func()) {
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

	tp := &http.Transport{
		MaxIdleConns:      1,
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: tp,
		Timeout:   3 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	eddieCmd := exec.CommandContext(ctx, "./eddie", "-c", configPath, "-d", "-l", "stdout")
	eddieCmd.Stdout = os.Stdout
	eddieCmd.Stderr = os.Stderr
	if err := eddieCmd.Start(); err != nil {
		t.Fatalf("error starting egress eddie binary: %v", err)
	}

	time.Sleep(time.Second)

	stop := func() {
		cancel()

		if err := eddieCmd.Wait(); err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				if exitErr.ExitCode() > 0 || (exitErr.ExitCode() == -1 && len(exitErr.Stderr) != 0) {
					t.Errorf("egress eddie exited with error: %v", err)
				}
			}
		}
		os.Remove(configPath)

		iptablesCmd(t, false, "-F")
		iptablesCmd(t, true, "-F")
	}

	return client, stop
}
