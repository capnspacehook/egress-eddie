package main

import (
	"context"
	"net"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/anmitsu/go-shlex"
)

func getHTTPClients() (*http.Client, *http.Client) {
	dialer := net.Dialer{
		FallbackDelay: -1,
	}
	tp4 := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		MaxIdleConns:      1,
		DisableKeepAlives: true,
	}
	tp6 := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp6", addr)
		},
		MaxIdleConns:      1,
		DisableKeepAlives: true,
	}

	client4 := &http.Client{
		Transport: tp4,
		Timeout:   3 * time.Second,
	}
	client6 := &http.Client{
		Transport: tp6,
		Timeout:   3 * time.Second,
	}

	return client4, client6
}

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
