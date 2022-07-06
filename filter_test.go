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
	"debian.org",
	"facebook.com",
	"google.com",
	"gist.github.com",
	"twitter.com",
]`

	client4, client6, stop := initFilters(
		t,
		configStr,
		[]string{
			"-A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j NFQUEUE --queue-num 1",
			"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1000",
			"-A OUTPUT -p tcp --dport 443 -m state --state NEW -j NFQUEUE --queue-num 1001",
		},
		[]string{
			"-A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j NFQUEUE --queue-num 10",
			"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1010",
			"-A OUTPUT -p tcp --dport 443 -m state --state NEW -j NFQUEUE --queue-num 1011",
		},
	)
	t.Cleanup(stop)

	is := is.New(t)

	t.Run("allowed requests", func(t *testing.T) {
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
	})

	t.Run("blocked requests", func(t *testing.T) {
		err := makeHTTPReqs(client4, client6, "https://microsoft.com")
		is.True(reqFailed(err)) // request to disallowed hostname should fail

		err = makeHTTPReqs(client4, client6, "https://ggoogle.com")
		is.True(reqFailed(err)) // test subdomain matching works correctly

		_, err = client4.Get("https://1.1.1.1")
		is.True(reqFailed(err)) // request to IPv4 IP of disallowed hostname should fail
		_, err = client6.Get("https://[2606:4700:4700::1111]")
		is.True(reqFailed(err)) // request to IPv6 IP of disallowed hostname should fail
	})

	t.Run("MX", func(t *testing.T) {
		mailDomains, err := net.DefaultResolver.LookupMX(getTimeout(t), "twitter.com")
		is.NoErr(err) // MX request to allowed hostname should succeed

		for _, mailDomain := range mailDomains {
			_, err = net.DefaultResolver.LookupNetIP(getTimeout(t), "ip4", mailDomain.Host)
			is.NoErr(err) // IPv4 lookup of allowed mail hostname should succeed
			_, err = net.DefaultResolver.LookupNetIP(getTimeout(t), "ip6", mailDomain.Host)
			is.NoErr(err) // IPv6 lookup of allowed mail hostname should succeed
		}
	})

	t.Run("NS", func(t *testing.T) {
		nameServers, err := net.DefaultResolver.LookupNS(getTimeout(t), "facebook.com")
		is.NoErr(err) // NS request to allowed hostname should succeed

		for _, nameServer := range nameServers {
			_, err = net.DefaultResolver.LookupNetIP(getTimeout(t), "ip4", nameServer.Host)
			is.NoErr(err) // IPv4 lookup of allowed name server should succeed
			_, err = net.DefaultResolver.LookupNetIP(getTimeout(t), "ip6", nameServer.Host)
			is.NoErr(err) // IPv6 lookup of allowed name server should succeed
		}
	})

	t.Run("SRV", func(t *testing.T) {
		_, servers, err := net.DefaultResolver.LookupSRV(getTimeout(t), "https", "tcp", "deb.debian.org")
		is.NoErr(err) // SRV request to allowed hostname should succeed

		for _, server := range servers {
			_, err = net.DefaultResolver.LookupNetIP(getTimeout(t), "ip4", server.Target)
			is.NoErr(err) // IPv4 lookup of allowed server should succeed
			_, err = net.DefaultResolver.LookupNetIP(getTimeout(t), "ip6", server.Target)
			is.NoErr(err) // IPv6 lookup of allowed server should succeed
		}
	})

	t.Run("expired IP", func(t *testing.T) {
		addrs4, err := net.DefaultResolver.LookupNetIP(getTimeout(t), "ip4", "google.com")
		is.NoErr(err) // IPv4 lookup of allowed hostname should succeed
		addrs6, err := net.DefaultResolver.LookupNetIP(getTimeout(t), "ip6", "google.com")
		is.NoErr(err) // IPv6 lookup of allowed hostname should succeed

		time.Sleep(4 * time.Second) // wait until IPs should expire

		_, err = client4.Get("https://" + addrs4[0].Unmap().String())
		is.True(reqFailed(err)) // request to expired IPv4 IP should fail
		_, err = client6.Get("https://[" + addrs6[0].Unmap().String() + "]")
		is.True(reqFailed(err)) // request to expired IPv6 IP should fail
	})
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
			"-A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j NFQUEUE --queue-num 1",
			"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1000",
		},
		[]string{
			"-A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j NFQUEUE --queue-num 10",
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

	addrs, err := net.DefaultResolver.LookupNetIP(getTimeout(t), "ip4", "digitalocean.com")
	is.NoErr(err)

	client4, _, stop := initFilters(
		t,
		configStr,
		[]string{
			"-A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j NFQUEUE --queue-num 1",
			"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 100",
			"-A OUTPUT -p tcp --dport 80 -m state --state NEW -j NFQUEUE --queue-num 1001",
		},
		[]string{
			"-A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j NFQUEUE --queue-num 10",
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

	_, err = net.DefaultResolver.LookupNetIP(getTimeout(t), "ip4", "microsoft.com")
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

func getTimeout(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)

	return ctx
}
