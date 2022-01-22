package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	configPath string
	debug      bool
	logPath    string
	testConfig bool
)

func init() {
	flag.StringVar(&configPath, "c", "egress-eddie.toml", "path of the config file")
	flag.BoolVar(&debug, "d", false, "enable debug logging")
	flag.StringVar(&logPath, "l", "egress-eddie.log", "path to log to")
	flag.BoolVar(&testConfig, "t", false, "validate the config and exit")
}

func main() {
	flag.Parse()

	logCfg := zap.NewProductionConfig()
	logCfg.OutputPaths = []string{logPath}
	if debug {
		logCfg.Level.SetLevel(zap.DebugLevel)
	}
	logCfg.EncoderConfig.TimeKey = "time"
	logCfg.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	logCfg.DisableCaller = true

	logger, err := logCfg.Build()
	if err != nil {
		log.Fatalf("error creating logger: %v", err)
	}

	config, err := ParseConfig(configPath)
	if testConfig {
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing config: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if err != nil {
		logger.Fatal("error parsing config", zap.NamedError("error", err))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)

	filters, err := StartFilters(ctx, logger, config)
	if err != nil {
		logger.Fatal("error starting filters", zap.NamedError("error", err))
	}
	logger.Info("started filtering")

	defer func() {
		cancel()
		logger.Info("stopping filters")
		filters.Stop()
	}()

	numAllowedSyscalls, err := installSeccompFilters(logger, config.SelfDNSQueue != 0)
	if err != nil {
		logger.Error("error setting seccomp rules", zap.NamedError("error", err))
		return
	}
	logger.Info("applied seccomp filters", zap.Int("syscalls.allowed", numAllowedSyscalls))

	<-ctx.Done()
}
