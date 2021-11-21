package main

import (
	"context"
	"net"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/anmitsu/go-shlex"
	"github.com/matryer/is"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestFiltering(t *testing.T) {
	configStr := `
inboundDNSQueue = 1
ipv6 = false

[[filters]]
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
		"-A OUTPUT -p udp --dport 53 -m owner --uid-owner root -j NFQUEUE --queue-num 1000",
		"-A OUTPUT -p tcp --dport 443 -m owner --uid-owner root -m state --state NEW -j NFQUEUE --queue-num 1001",
	)

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
	reqTimedOut(is, err) // request to disallowed hostname should timeout

	_, err = client.Get("https://ggoogle.com")
	reqTimedOut(is, err) // test subdomain matching works correctly

	_, err = client.Get("https://1.1.1.1")
	reqTimedOut(is, err) // request to IP of disallowed hostname should timeout

	addrs, err := net.LookupHost("google.com")
	is.NoErr(err) // lookup of allowed hostname should succeed

	time.Sleep(4 * time.Second) // wait until IPs should expire

	_, err = client.Get("https://" + addrs[0])
	reqTimedOut(is, err) // request to expired IP should timeout

	stop()
}

func TestCaching(t *testing.T) {
	configStr := `
inboundDNSQueue = 1
selfDNSQueue = 100
ipv6 = false

[[filters]]
dnsQueue = 9999 # not used
trafficQueue = 1001
ipv6 = false
reCacheEvery = "1m"
cacheHostnames = [
	"digitalocean.com",
]`

	is := is.New(t)

	addrs, err := net.LookupIP("digitalocean.com")
	is.NoErr(err)

	client, stop := initFilters(
		t,
		configStr,
		"-A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1",
		"-A OUTPUT -p udp --dport 53 -m owner --uid-owner root -j NFQUEUE --queue-num 100",
		"-A OUTPUT -p tcp --dport 80 -m owner --uid-owner root -m state --state NEW -j NFQUEUE --queue-num 1001",
	)

	// wait until hostnames responses are cached by filters
	time.Sleep(3 * time.Second)

	for _, addr := range addrs {
		// skip IPv6 addresses, causes an error when preforming a GET request
		if addr.To4() == nil {
			continue
		}

		resp, err := client.Get("http://" + addr.String())
		is.NoErr(err) // request to IP of cached hostname should succeed
		resp.Body.Close()
	}

	stop()
}

func initFilters(t *testing.T, configStr string, iptablesRules ...string) (*http.Client, func()) {
	config, err := parseConfigBytes([]byte(configStr))
	if err != nil {
		t.Fatalf("error parsing config: %v", err)
	}

	iptablesCmd(t, "-F")
	for _, command := range iptablesRules {
		iptablesCmd(t, command)
	}

	logCfg := zap.NewProductionConfig()
	logCfg.OutputPaths = []string{"stderr"}
	logCfg.Level.SetLevel(zap.DebugLevel)
	logCfg.EncoderConfig.TimeKey = "time"
	logCfg.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	logCfg.DisableCaller = true

	logger, err := logCfg.Build()
	if err != nil {
		t.Fatalf("error creating logger: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	filters, err := StartFilters(ctx, logger, config)
	if err != nil {
		t.Fatalf("error starting filters: %v", err)
	}

	tp := &http.Transport{
		MaxIdleConns:      1,
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: tp,
		Timeout:   3 * time.Second,
	}

	stop := func() {
		cancel()
		filters.Stop()
		iptablesCmd(t, "-F")
	}

	return client, stop
}

func iptablesCmd(t *testing.T, args string) {
	splitArgs, err := shlex.Split(args, true)
	if err != nil {
		t.Fatalf("error spitting command %v: %v", args, err)
	}

	if err := exec.Command("iptables", splitArgs...).Run(); err != nil {
		t.Fatalf("error running command %v: %v", args, err)
	}
}

func reqTimedOut(is *is.I, err error) {
	timeoutErr, ok := err.(interface{ Timeout() bool })
	is.True(ok)
	if ok {
		is.True(timeoutErr.Timeout())
	}
}
