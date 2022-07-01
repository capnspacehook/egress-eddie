//go:build !test_binary

package main

import (
	"context"
	"net/http"
	"testing"

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

	client4, client6 := getHTTPClients()

	stop := func() {
		cancel()
		filters.Stop()
		iptablesCmd(t, false, "-F")
		iptablesCmd(t, true, "-F")
	}

	return client4, client6, stop
}
