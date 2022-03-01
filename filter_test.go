package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/matryer/is"
)

func TestFiltering(t *testing.T) {
	configStr := `
inboundDNSQueue = 1
ipv6 = false

[[filters]]
name = "test"
dnsQueue = 1000
trafficQueue = 1001
ipv6 = false
allowAnswersFor = "3s"
allowedHostnames = [
	"google.com",
	"gist.github.com",
]`

	client, stop := initFilters(
		t,
		configStr,
		"-A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1",
		"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1000",
		"-A OUTPUT -p tcp --dport 443 -m state --state NEW -j NFQUEUE --queue-num 1001",
	)
	defer stop()

	is := is.New(t)

	resp, err := client.Get("https://google.com")
	is.NoErr(err) // request to allowed hostname should succeed
	resp.Body.Close()

	resp, err = client.Get("https://news.google.com")
	is.NoErr(err) // request to allowed subdomain of hostname should succeed
	resp.Body.Close()

	resp, err = client.Get("https://gist.github.com")
	is.NoErr(err) // request to allowed hostname should succeed
	resp.Body.Close()

	resp, err = client.Get("https://github.com")
	is.NoErr(err) // request to allowed hostname from response CNAME should succeed
	resp.Body.Close()

	_, err = client.Get("https://microsoft.com")
	is.True(reqFailed(err)) // request to disallowed hostname should fail

	_, err = client.Get("https://ggoogle.com")
	is.True(reqFailed(err)) // test subdomain matching works correctly

	_, err = client.Get("https://1.1.1.1")
	is.True(reqFailed(err)) // request to IP of disallowed hostname should fail

	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip4", "google.com")
	is.NoErr(err) // lookup of allowed hostname should succeed

	time.Sleep(4 * time.Second) // wait until IPs should expire

	_, err = client.Get("https://" + addrs[0].Unmap().String())
	is.True(reqFailed(err)) // request to expired IP should fail
}

func TestAllowAll(t *testing.T) {
	configStr := `
inboundDNSQueue = 1
ipv6 = false

[[filters]]
name = "test"
dnsQueue = 1000
ipv6 = false
allowAllHostnames = true`

	client, stop := initFilters(
		t,
		configStr,
		"-A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1",
		"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1000",
	)
	defer stop()

	is := is.New(t)

	resp, err := client.Get("https://harmony.shinesparkers.net")
	is.NoErr(err) // request to hostname should succeed
	resp.Body.Close()
}

func TestCaching(t *testing.T) {
	configStr := `
inboundDNSQueue = 1
selfDNSQueue = 100
ipv6 = false

[[filters]]
name = "test"
trafficQueue = 1001
ipv6 = false
reCacheEvery = "1m"
cachedHostnames = [
	"digitalocean.com",
]`

	is := is.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "digitalocean.com")
	is.NoErr(err)

	client, stop := initFilters(
		t,
		configStr,
		"-A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1",
		"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 100",
		"-A OUTPUT -p tcp --dport 80 -m state --state NEW -j NFQUEUE --queue-num 1001",
	)
	defer stop()

	// wait until hostnames responses are cached by filters
	time.Sleep(3 * time.Second)

	for _, addr := range addrs {
		// skip IPv6 addresses, causes an error when preforming a GET request
		addr = addr.Unmap()

		resp, err := client.Get("http://" + addr.String())
		is.NoErr(err) // request to IP of cached hostname should succeed
		resp.Body.Close()
	}

	_, err = net.DefaultResolver.LookupNetIP(ctx, "ip4", "microsoft.com")
	is.True(reqFailed(err)) // lookup of disallowed domain should fail
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
