package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/anmitsu/go-shlex"
	"github.com/florianl/go-nfqueue"
	"github.com/matryer/is"
	"go.uber.org/goleak"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	binaryTests = flag.Bool("binary-tests", false, "use compiled binary to test with landlock and seccomp enabled")
	eddieBinary = flag.String("eddie-binary", "./egress-eddie", "path to compiled egress-eddie binary")
	// Github hosted runners don't support IPv6, so can't test with IPv6
	// in Github Actions
	// see https://github.com/actions/runner-images/issues/668
	enableIPv6 = flag.Bool("enable-ipv6", true, "enable testing IPv6")
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

	client4, client6 := initFilters(
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
		if *enableIPv6 {
			_, err = client6.Get("https://[2606:4700:4700::1111]")
			is.True(reqFailed(err)) // request to IPv6 IP of disallowed hostname should fail
		}
	})

	t.Run("MX", func(t *testing.T) {
		mailDomains, err := net.DefaultResolver.LookupMX(getTimeout(t), "twitter.com")
		is.NoErr(err) // MX request to allowed hostname should succeed

		for _, mailDomain := range mailDomains {
			_, _, err = lookupIPs(t, mailDomain.Host)
			is.NoErr(err) // lookup of allowed mail hostname should succeed
		}
	})

	t.Run("NS", func(t *testing.T) {
		nameServers, err := net.DefaultResolver.LookupNS(getTimeout(t), "facebook.com")
		is.NoErr(err) // NS request to allowed hostname should succeed

		for _, nameServer := range nameServers {
			_, _, err = lookupIPs(t, nameServer.Host)
			is.NoErr(err) // lookup of allowed name server should succeed
		}
	})

	t.Run("SRV", func(t *testing.T) {
		_, servers, err := net.DefaultResolver.LookupSRV(getTimeout(t), "https", "tcp", "deb.debian.org")
		is.NoErr(err) // SRV request to allowed hostname should succeed

		for _, server := range servers {
			_, _, err = lookupIPs(t, server.Target)
			is.NoErr(err) // lookup of allowed server should succeed
		}
	})

	t.Run("expired IP", func(t *testing.T) {
		addrs4, addrs6, err := lookupIPs(t, "google.com")
		is.NoErr(err) // lookup of allowed hostname should succeed

		time.Sleep(4 * time.Second) // wait until IPs should expire

		_, err = client4.Get("https://" + addrs4[0].Unmap().String())
		is.True(reqFailed(err)) // request to expired IPv4 IP should fail
		if *enableIPv6 {
			_, err = client6.Get("https://[" + addrs6[0].Unmap().String() + "]")
			is.True(reqFailed(err)) // request to expired IPv6 IP should fail
		}
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

	client4, client6 := initFilters(
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

	client4, _ := initFilters(
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

func TestFiltersStart(t *testing.T) {
	if *binaryTests {
		t.Skip()
	}

	configBytes := []byte(`
inboundDNSQueue.ipv6 = 10
selfDNSQueue.ipv6 = 110

[[filters]]
name = "test"
dnsQueue.ipv6 = 1010
trafficQueue.ipv6 = 1011
reCacheEvery = "1m"
cachedHostnames = [
	"example.com",
]
allowAnswersFor = "1s"
allowedHostnames = [
	"test.org"
]`)

	is := is.New(t)

	config, err := parseConfigBytes(configBytes)
	is.NoErr(err)

	config.enforcerCreator = newMockEnforcer

	t.Run("filters waiting", func(t *testing.T) {
		initMockEnforcers()

		ctx, cancel := context.WithCancel(context.Background())
		f, err := CreateFilters(ctx, zap.NewNop(), config, false)
		is.NoErr(err)
		t.Cleanup(func() {
			cancel()
			f.Stop()
		})

		finishedAt := make(chan time.Time)

		go func() {
			mockEnforcers[config.InboundDNSQueue.IPv6].hook(nfqueue.Attribute{})
			t.Log("finished DNS reply queue")
			finishedAt <- time.Now()
		}()
		// the self-filter will be the first filter
		testFilter := config.Filters[1]
		go func() {
			mockEnforcers[testFilter.DNSQueue.IPv6].hook(nfqueue.Attribute{})
			t.Log("finished DNS request queue")
			finishedAt <- time.Now()
		}()
		go func() {
			mockEnforcers[testFilter.TrafficQueue.IPv6].hook(nfqueue.Attribute{})
			t.Log("finished generic queue")
			finishedAt <- time.Now()
		}()

		time.Sleep(time.Second)
		startedAt := time.Now()
		f.Start()
		t.Log("starting filters")

		for i := 0; i < 3; i++ {
			t := <-finishedAt
			is.True(t.After(startedAt)) // packet handling should have finished after filters were started
		}
	})

	t.Run("stopping without starting", func(t *testing.T) {
		// test that goroutines are cleanly shutdown
		defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

		// use real nfqueues
		config.enforcerCreator = nil
		ctx, cancel := context.WithCancel(context.Background())
		f, err := CreateFilters(ctx, zap.NewNop(), config, false)
		is.NoErr(err)

		cancel()
		f.Stop()
	})
}

func initFilters(t *testing.T, configStr string, iptablesRules, ip6tablesRules []string) (*http.Client, *http.Client) {
	if *binaryTests {
		return initBinaryFilters(t, configStr, iptablesRules, ip6tablesRules)
	}
	return initStandardFilters(t, configStr, iptablesRules, ip6tablesRules)
}

func initBinaryFilters(t *testing.T, configStr string, iptablesRules, ip6tablesRules []string) (*http.Client, *http.Client) {
	f, err := os.CreateTemp("", "egress_eddie")
	if err != nil {
		t.Fatalf("error creating config file: %v", err)
	}
	configPath := f.Name()
	t.Cleanup(func() { os.Remove(configPath) })

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

	eddieCmd := exec.Command(*eddieBinary, "-c", configPath, "-d", "-f", "-l", "stdout")
	eddieCmd.Stdout = os.Stdout
	eddieCmd.Stderr = os.Stderr
	if err := eddieCmd.Start(); err != nil {
		t.Fatalf("error starting egress eddie binary: %v", err)
	}

	time.Sleep(time.Second)

	client4, client6 := getHTTPClients()

	t.Cleanup(func() {
		err := eddieCmd.Process.Signal(os.Interrupt)
		if err != nil {
			t.Errorf("error killing egress eddie process: %v", err)
		}

		if err := eddieCmd.Wait(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				t.Errorf("egress eddie exited with error: %v", err)
			}
		}
		os.Remove(configPath)

		iptablesCmd(t, false, "-F")
		iptablesCmd(t, true, "-F")
	})

	return client4, client6
}

func initStandardFilters(t *testing.T, configStr string, iptablesRules, ip6tablesRules []string) (*http.Client, *http.Client) {
	config, err := parseConfigBytes([]byte(configStr))
	if err != nil {
		t.Fatalf("error parsing config: %v", err)
	}

	iptablesCmd(t, false, "-F")
	for _, command := range iptablesRules {
		iptablesCmd(t, false, command)
	}

	iptablesCmd(t, true, "-F")
	for _, command := range ip6tablesRules {
		iptablesCmd(t, true, command)
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
	filters, err := CreateFilters(ctx, logger, config, true)
	if err != nil {
		t.Fatalf("error starting filters: %v", err)
	}
	filters.Start()

	client4, client6 := getHTTPClients()

	t.Cleanup(func() {
		cancel()
		filters.Stop()
		iptablesCmd(t, false, "-F")
		iptablesCmd(t, true, "-F")
	})

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

func makeHTTPReqs(client4, client6 *http.Client, addr string) error {
	if client4 != nil {
		resp, err := client4.Get(addr)
		if err != nil {
			return err
		}
		resp.Body.Close()
	}

	if *enableIPv6 && client6 != nil {
		resp, err := client6.Get(addr)
		if err != nil {
			return err
		}
		resp.Body.Close()
	}

	return nil
}

func lookupIPs(t *testing.T, host string) (ips4 []netip.Addr, ips6 []netip.Addr, err error) {
	ips4, err = net.DefaultResolver.LookupNetIP(getTimeout(t), "ip4", host)
	if err != nil {
		return nil, nil, err
	}

	if *enableIPv6 {
		ips6, err = net.DefaultResolver.LookupNetIP(getTimeout(t), "ip6", host)
		if err != nil {
			return nil, nil, err
		}
	}

	return ips4, ips6, nil
}

func reqFailed(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return false
}

func getTimeout(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)

	return ctx
}
