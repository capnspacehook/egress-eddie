package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/anmitsu/go-shlex"
)

func makeHTTPReqs(client4, client6 *http.Client, addr string) error {
	if client4 != nil {
		resp, err := client4.Get(addr)
		if err != nil {
			return err
		}
		resp.Body.Close()
	}

	if client6 != nil {
		resp, err := client6.Get(addr)
		if err != nil {
			return err
		}
		resp.Body.Close()
	}

	return nil
}

func reqFailed(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	return false
}

func getTimeout(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)

	return ctx
}

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
