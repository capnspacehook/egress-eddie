//go:build !test_binary

package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func initFilters(t *testing.T, configStr string, iptablesRules ...string) (*http.Client, func()) {
	config, err := parseConfigBytes([]byte(configStr))
	if err != nil {
		t.Fatalf("error parsing config: %v", err)
	}

	iptablesCmd(t, "-F")
	for _, command := range iptablesRules {
		iptablesCmd(t, command)
	}

	tp := &http.Transport{
		MaxIdleConns:      1,
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: tp,
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
		iptablesCmd(t, "-F")
	}

	return client, stop
}
