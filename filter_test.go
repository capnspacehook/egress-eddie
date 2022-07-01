package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/matryer/is"
)

func TestFiltering(t *testing.T) {
	configStr := `
inboundDNSQueue.ipv4 = 1
inboundDNSQueue.ipv6 = 10

[[filters]]
name = "test"
dnsQueue.ipv4 = 1000
dnsQueue.ipv6 = 1010
trafficQueue.ipv4 = 1001
trafficQueue.ipv6 = 1011
allowAnswersFor = "3s"
allowedHostnames = [
	"google.com",
	"gist.github.com",
]`

	client4, client6, stop := initFilters(
		t,
		configStr,
		[]string{
			"-A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1",
			"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1000",
			"-A OUTPUT -p tcp --dport 443 -m state --state NEW -j NFQUEUE --queue-num 1001",
		},
		[]string{
			"-A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 10",
			"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1010",
			"-A OUTPUT -p tcp --dport 443 -m state --state NEW -j NFQUEUE --queue-num 1011",
		},
	)
	t.Cleanup(stop)

	is := is.New(t)

	err := makeHTTPReqs(client4, client6, "https://google.com")
	is.NoErr(err) // request to allowed hostname should succeed

	err = makeHTTPReqs(client4, client6, "https://news.google.com")
	is.NoErr(err) // request to allowed subdomain of hostname should succeed

	// TODO: github.com does not have AAAA record, so this will fail over
	// IPv6. Find other website that will work here
	err = makeHTTPReqs(client4, nil, "https://gist.github.com")
	is.NoErr(err) // request to allowed hostname should succeed

	err = makeHTTPReqs(client4, nil, "https://github.com")
	is.NoErr(err) // request to allowed hostname from response CNAME should succeed

	err = makeHTTPReqs(client4, client6, "https://microsoft.com")
	is.True(reqFailed(err)) // request to disallowed hostname should fail

	err = makeHTTPReqs(client4, client6, "https://.com")
	is.True(reqFailed(err)) // test subdomain matching works correctly

	_, err = client4.Get("https://1.1.1.1")
	is.True(reqFailed(err)) // request to IPv4 IP of disallowed hostname should fail
	_, err = client6.Get("https://[2606:4700:4700::1111]")
	is.True(reqFailed(err)) // request to IPv6 IP of disallowed hostname should fail

	addrs4, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip4", "google.com")
	is.NoErr(err) // IPv4 lookup of allowed hostname should succeed
	addrs6, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip6", "google.com")
	is.NoErr(err) // IPv6 lookup of allowed hostname should succeed

	time.Sleep(4 * time.Second) // wait until IPs should expire

	_, err = client4.Get("https://" + addrs4[0].Unmap().String())
	is.True(reqFailed(err)) // request to expired IPv4 IP should fail
	_, err = client6.Get("https://[" + addrs6[0].Unmap().String() + "]")
	is.True(reqFailed(err)) // request to expired IPv6 IP should fail
}

func TestAllowAll(t *testing.T) {
	configStr := `
inboundDNSQueue.ipv4 = 1
inboundDNSQueue.ipv6 = 10

[[filters]]
name = "test"
dnsQueue.ipv4 = 1000
dnsQueue.ipv6 = 1010
allowAllHostnames = true`

	client4, client6, stop := initFilters(
		t,
		configStr,
		[]string{
			"-A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1",
			"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1000",
		},
		[]string{
			"-A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 10",
			"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1010",
		},
	)
	t.Cleanup(stop)

	is := is.New(t)

	err := makeHTTPReqs(client4, client6, "https://harmony.shinesparkers.net")
	is.NoErr(err) // request to hostname should succeed
}

func TestCaching(t *testing.T) {
	configStr := `
inboundDNSQueue.ipv4 = 1
inboundDNSQueue.ipv6 = 10
selfDNSQueue.ipv4 = 100
selfDNSQueue.ipv6 = 110

[[filters]]
name = "test"
trafficQueue.ipv4 = 1001
trafficQueue.ipv6 = 1011
reCacheEvery = "1m"
cachedHostnames = [
	"digitalocean.com",
]`

	is := is.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "digitalocean.com")
	is.NoErr(err)

	client4, _, stop := initFilters(
		t,
		configStr,
		[]string{
			"-A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1",
			"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 100",
			"-A OUTPUT -p tcp --dport 80 -m state --state NEW -j NFQUEUE --queue-num 1001",
		},
		[]string{
			"-A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 10",
			"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 110",
			"-A OUTPUT -p tcp --dport 80 -m state --state NEW -j NFQUEUE --queue-num 1011",
		},
	)
	t.Cleanup(stop)

	// wait until hostnames responses are cached by filters
	time.Sleep(3 * time.Second)

	for _, addr := range addrs {
		// skip IPv6 addresses, causes an error when preforming a GET request
		addr = addr.Unmap()

		resp, err := client4.Get("http://" + addr.String())
		is.NoErr(err) // request to IP of cached hostname should succeed
		resp.Body.Close()
	}

	_, err = net.DefaultResolver.LookupNetIP(ctx, "ip4", "microsoft.com")
	is.True(reqFailed(err)) // lookup of disallowed domain should fail
}

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
