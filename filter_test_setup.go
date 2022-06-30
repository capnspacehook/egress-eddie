//go:build !test_binary

package main

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func initFilters(t *testing.T, configStr string, iptablesRules, ip6tablesRules []string) (*http.Client, *http.Client, func()) {
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

	var dialer net.Dialer
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

	stop := func() {
		cancel()
		filters.Stop()
		iptablesCmd(t, false, "-F")
		iptablesCmd(t, true, "-F")
	}

	return client4, client6, stop
}
