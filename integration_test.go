package egresseddie

import (
	"context"
	"errors"
	"flag"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/anmitsu/go-shlex"
	"github.com/florianl/go-nfqueue/v2"
	"github.com/matryer/is"
	"go.uber.org/goleak"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sys/unix"

	"github.com/capnspacehook/egress-eddie/resolve"
)

var (
	binaryTests = flag.Bool("binary-tests", false, "use compiled binary to test with landlock and seccomp enabled")
	eddieBinary = flag.String("eddie-binary", "./egress-eddie", "path to compiled egress-eddie binary")
	// Github hosted runners don't support IPv6, so can't test with IPv6
	// in Github Actions
	// see https://github.com/actions/runner-images/issues/668
	enableIPv6 = flag.Bool("enable-ipv6", true, "enable testing IPv6")
)

func requireRoot(t *testing.T) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("skipping test because not running as root")
	}
}

func TestIntegrationFiltering(t *testing.T) {
	requireRoot(t)

	configStr := `
dnsResponseQueue = 1

[[filters]]
name = "test"
dnsQueue = 1000
trafficQueue = 1001
allowAnswersFor = "3s"
allowedDomains = [
	"google.com",
	"*.google.com",
	"gist.github.com",

	"*.debian.org",

	"twitter.com",
]
allowedTargets = [
	"github.com",

	"debian.map.fastly.net",

	"aspmx.*.google.com",
	"alt[1-4].aspmx.*.google.com",
]`

	initFilters(
		t,
		configStr,
		[]string{
			"-A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j NFQUEUE --queue-num 1",
			"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1000",
			"-A OUTPUT -p tcp --dport 443 -m state --state NEW -j NFQUEUE --queue-num 1001",
		},
	)
	client4, client6 := getHTTPClients()

	t.Run("allowed requests", func(t *testing.T) {
		is := is.New(t)

		err := makeHTTPReqs(client4, client6, "https://google.com")
		is.NoErr(err) // request to allowed domain should succeed

		err = makeHTTPReqs(client4, client6, "https://gOOgLe.cOm")
		is.NoErr(err) // request to allowed domain with different casing should succeed

		err = makeHTTPReqs(client4, client6, "https://news.google.com")
		is.NoErr(err) // request to allowed subdomain of domain should succeed

		err = makeHTTPReqs(client4, client6, "https://NEWs.GOOGle.COm")
		is.NoErr(err) // request to allowed subdomain of domain with different casing should succeed

		// TODO: github.com does not have AAAA record, so this will fail over
		// IPv6. Find other website that will work here
		err = makeHTTPReqs(client4, nil, "https://gist.github.com")
		is.NoErr(err) // request to allowed domain should succeed

		err = makeHTTPReqs(client4, nil, "https://github.com")
		is.NoErr(err) // request to allowed domain from response CNAME should succeed
	})

	t.Run("blocked requests", func(t *testing.T) {
		is := is.New(t)

		err := makeHTTPReqs(client4, client6, "https://microsoft.com")
		is.True(reqFailed(err)) // request to disallowed domain should fail

		err = makeHTTPReqs(client4, client6, "https://ggoogle.com")
		is.True(reqFailed(err)) // request to disallowed domain should fail

		err = makeHTTPReqs(client4, client6, "https://blog.github.com")
		is.True(reqFailed(err)) // test subdomain matching works correctly

		resp, err := client4.Get("https://1.1.1.1")
		is.True(reqFailed(err)) // request to IPv4 IP of disallowed domain should fail
		if resp != nil {
			resp.Body.Close()
		}
		if *enableIPv6 {
			resp, err := client6.Get("https://[2606:4700:4700::1111]")
			is.True(reqFailed(err)) // request to IPv6 IP of disallowed domain should fail
			if resp != nil {
				resp.Body.Close()
			}
		}
	})

	t.Run("SRV", func(t *testing.T) {
		is := is.New(t)

		_, servers, err := net.DefaultResolver.LookupSRV(getTimeout(t), "https", "tcp", "deb.debian.org")
		is.NoErr(err) // SRV request to allowed domain should succeed

		for _, server := range servers {
			_, _, err = lookupIPs(t, server.Target)
			is.NoErr(err) // lookup of allowed server should succeed
		}
	})

	t.Run("MX", func(t *testing.T) {
		is := is.New(t)

		mailDomains, err := net.DefaultResolver.LookupMX(getTimeout(t), "twitter.com")
		is.NoErr(err) // MX request to allowed domain should succeed

		for _, mailDomain := range mailDomains {
			_, _, err = lookupIPs(t, mailDomain.Host)
			is.NoErr(err) // lookup of allowed mail domain should succeed
		}
	})

	t.Run("expired IP", func(t *testing.T) {
		is := is.New(t)

		addrs4, addrs6, err := lookupIPs(t, "google.com")
		is.NoErr(err) // lookup of allowed domain should succeed

		time.Sleep(4 * time.Second) // wait until IPs should expire

		resp, err := client4.Get("https://" + addrs4[0].Unmap().String())
		is.True(reqFailed(err)) // request to expired IPv4 IP should fail
		if resp != nil {
			resp.Body.Close()
		}
		if *enableIPv6 {
			resp, err := client6.Get("https://[" + addrs6[0].Unmap().String() + "]")
			is.True(reqFailed(err)) // request to expired IPv6 IP should fail
			if resp != nil {
				resp.Body.Close()
			}
		}
	})
}

func TestIntegrationAllowAll(t *testing.T) {
	requireRoot(t)

	const configFilters = `
[[filters]]
name = "test"
dnsQueue = 100
trafficQueue = 1000
allowAnswersFor = "1m"
allowAllDomains = true`

	tests := []struct {
		name          string
		globalConfig  string
		iptablesRules []string
	}{
		{
			name: "udp",
			globalConfig: `
dnsResponseQueue = 1`,
			iptablesRules: []string{
				"-A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j NFQUEUE --queue-num 1",
				"-A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j NFQUEUE --queue-num 100",
				"-A OUTPUT -p tcp --dport 80 -m state --state NEW -j NFQUEUE --queue-num 1000",
			},
		}, {
			name: "doh",
			globalConfig: `
dnsResponseQueue = 1
resolveWithDoH = true
dohURL = "https://1.1.1.1"
dohServerName = "one.one.one.one"`,
			iptablesRules: []string{
				"-A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT",
				"-A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j NFQUEUE --queue-num 100",
				"-A OUTPUT -p tcp --dport 80 -m state --state NEW -j NFQUEUE --queue-num 1000",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initFilters(
				t,
				tt.globalConfig+configFilters,
				tt.iptablesRules,
			)
			client4, client6 := getHTTPClients()

			is := is.New(t)

			err := makeHTTPReqs(client4, client6, "http://harmony.shinesparkers.net")
			is.NoErr(err) // request to domain should succeed

			err = makeHTTPReqs(client4, client6, "http://1.1.1.1")
			is.True(reqFailed(err)) // request to IP not from DNS response should fail
		})
	}
}

func TestIntegrationCaching(t *testing.T) {
	requireRoot(t)

	tests := []struct {
		name          string
		configStr     string
		iptablesRules []string
	}{
		{
			name: "udp",
			configStr: `
dnsResponseQueue = 1
selfDNSQueue = 100
resolverIP = "1.1.1.1"

[[filters]]
name = "test"
trafficQueue = 1001
reCacheEvery = "1m"
cachedDomains = [
	"deb.debian.org",
]
cachedTargets = [
	"debian.map.fastlydns.net",
]`,
			iptablesRules: []string{
				"-A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j NFQUEUE --queue-num 1",
				"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 100",
				"-A OUTPUT -p tcp --dport 80 -m state --state NEW -j NFQUEUE --queue-num 1001",
				"-A OUTPUT -p tcp --dport 443 -m state --state NEW -j DROP",
			},
		}, {
			name: "doh",
			configStr: `
dnsResponseQueue = 1
selfDNSQueue = 100
resolveWithDoH = true
dohURL = "https://1.1.1.1"
dohServerName = "one.one.one.one"

[[filters]]
name = "test"
trafficQueue = 1001
reCacheEvery = "1m"
cachedDomains = [
	"deb.debian.org",
]
cachedTargets = [
	"debian.map.fastlydns.net",
]`,
			iptablesRules: []string{
				"-A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j DROP",
				"-A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 100",
				"-A OUTPUT -p tcp --dport 80 -m state --state NEW -j NFQUEUE --queue-num 1001",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			// resolve IPs before the filters are setup
			sender, err := resolve.NewUDPSender("1.1.1.1")
			is.NoErr(err)

			addrs, errs := resolve.Domain(getTimeout(t), "deb.debian.org", sender, nil)
			if len(errs) > 0 {
				t.Logf("errors resolving domain: %v", errs)
			}
			is.True(len(errs) == 0)

			initFilters(
				t,
				tt.configStr,
				tt.iptablesRules,
			)
			client4, _ := getHTTPClients()

			// wait until domains responses are cached by filters
			time.Sleep(3 * time.Second)

			for _, addr := range addrs {
				// skip IPv6 addresses, causes an error when preforming a GET request
				if addr.Is6() {
					continue
				}
				addr = addr.Unmap()

				resp, err := client4.Get("http://" + addr.String())
				is.NoErr(err) // request to IP of cached domain should succeed
				if resp != nil {
					resp.Body.Close()
				}
			}

			addrs, errs = resolve.Domain(getTimeout(t), "microsoft.com", sender, nil)
			is.True(len(errs) > 0)   // lookup of disallowed domain should fail
			is.True(len(addrs) == 0) // lookup of disallowed domain should return no IPs
		})
	}
}

func TestIntegrationFiltersStart(t *testing.T) {
	requireRoot(t)

	configBytes := []byte(`
dnsResponseQueue = 10
selfDNSQueue = 110

[[filters]]
name = "test"
dnsQueue = 1010
trafficQueue = 1011
reCacheEvery = "1m"
cachedDomains = [
	"example.com",
]
allowAnswersFor = "1s"
allowedDomains = [
	"test.org"
]`)

	is := is.New(t)

	config, err := parseConfigBytes(configBytes)
	is.NoErr(err)

	config.enforcerCreator = newMockEnforcer

	t.Run("filters waiting", func(t *testing.T) {
		is := is.New(t)

		initMockEnforcers()

		ctx, cancel := context.WithCancel(context.Background())
		f, err := CreateFilters(ctx, zap.NewNop(), config, false, false)
		is.NoErr(err)
		t.Cleanup(func() {
			cancel()
			f.Stop()
		})

		finishedAt := make(chan time.Time)

		go func() {
			mockEnforcers[config.DNSResponseQueue].hook(nfqueue.Attribute{})
			t.Log("finished DNS reply queue")
			finishedAt <- time.Now()
		}()
		// the self-filter will be the first filter
		testFilter := config.Filters[1]
		go func() {
			mockEnforcers[testFilter.DNSQueue].hook(nfqueue.Attribute{})
			t.Log("finished DNS request queue")
			finishedAt <- time.Now()
		}()
		go func() {
			mockEnforcers[testFilter.TrafficQueue].hook(nfqueue.Attribute{})
			t.Log("finished generic queue")
			finishedAt <- time.Now()
		}()

		time.Sleep(time.Second)
		startedAt := time.Now()
		f.Start()
		t.Log("starting filters")

		for range 3 {
			t := <-finishedAt
			is.True(t.After(startedAt)) // packet handling should have finished after filters were started
		}
	})

	t.Run("stopping without starting", func(t *testing.T) {
		is := is.New(t)

		// test that goroutines are cleanly shutdown
		defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

		// use real nfqueues
		config.enforcerCreator = nil
		ctx, cancel := context.WithCancel(context.Background())
		f, err := CreateFilters(ctx, zap.NewNop(), config, false, false)
		is.NoErr(err)

		cancel()
		f.Stop()
	})
}

func initFilters(t *testing.T, configStr string, iptablesRules []string) {
	t.Helper()

	switch {
	case *binaryTests:
		initBinaryFilters(t, configStr, iptablesRules)
	default:
		initStandardFilters(t, configStr, iptablesRules)
	}
}

func initBinaryFilters(t *testing.T, configStr string, iptablesRules []string) {
	t.Helper()

	if _, err := exec.LookPath(*eddieBinary); err != nil {
		t.Fatalf("finding egress eddie binary: %v", err)
	}
	if _, err := exec.LookPath("strace"); err != nil {
		t.Fatalf("finding strace: %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "config.toml")
	f, err := os.Create(configPath)
	if err != nil {
		t.Fatalf("creating config file: %v", err)
	}
	if _, err = f.WriteString(configStr); err != nil {
		t.Fatalf("writing config file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing config file: %v", err)
	}

	iptablesCmd(t, "-F")
	for _, command := range iptablesRules {
		iptablesCmd(t, command)
	}

	eddieCmd := exec.Command(*eddieBinary, "-c", configPath, "-d", "-f")
	eddieCmd.Stdout = os.Stdout
	eddieCmd.Stderr = os.Stderr
	eddieCmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	if err := eddieCmd.Start(); err != nil {
		t.Fatalf("starting egress eddie binary: %v", err)
	}

	time.Sleep(time.Second)

	t.Cleanup(func() {
		err := unix.Kill(-eddieCmd.Process.Pid, unix.SIGINT)
		if err != nil {
			t.Errorf("killing egress eddie process: %v", err)
		}

		done := make(chan struct{})
		go func() {
			err := eddieCmd.Wait()
			done <- struct{}{}
			if err != nil {
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					t.Errorf("egress eddie exited with error: %v", err)
				}
			}
		}()

		timeout := time.After(3 * time.Second)
		select {
		case <-done:
		case <-timeout:
			t.Error("timeout waiting for egress eddie process to finish")
			_ = eddieCmd.Process.Kill()
		}

		iptablesCmd(t, "-F")
	})
}

func initStandardFilters(t *testing.T, configStr string, iptablesRules []string) {
	t.Helper()

	config, err := parseConfigBytes([]byte(configStr))
	if err != nil {
		t.Fatalf("parsing config: %v", err)
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
		t.Fatalf("creating logger: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	filters, err := CreateFilters(ctx, logger, config, false, true)
	if err != nil {
		t.Fatalf("starting filters: %v", err)
	}
	filters.Start()

	t.Cleanup(func() {
		cancel()
		filters.Stop()
		iptablesCmd(t, "-F")
	})
}

func iptablesCmd(t *testing.T, args string) {
	t.Helper()

	splitArgs, err := shlex.Split(args, true)
	if err != nil {
		t.Fatalf("spitting command %v: %v", args, err)
	}

	if err := exec.Command("iptables", splitArgs...).Run(); err != nil {
		t.Fatalf("running command %v: %v", args, err)
	}
	if *enableIPv6 {
		if err := exec.Command("ip6tables", splitArgs...).Run(); err != nil {
			t.Fatalf("running command %v: %v", args, err)
		}
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
	t.Helper()

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
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	t.Cleanup(cancel)

	return ctx
}
