package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
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

	// Ensure the config and log files exist and we have permissions
	// to access them. This will also be done by landlock below, but
	// by manually checking and logging upon failure here, the error
	// message will be more clear.
	if _, err := os.Stat(configPath); err != nil {
		log.Fatalf("could not open config file: %v", err)
	}

	var logNormalFile bool
	if logPath != "stdout" && logPath != "stderr" {
		logNormalFile = true

		if _, err := os.Stat(logPath); err != nil {
			log.Fatalf("could not open log file: %v", err)
		}
	}

	// Try and apply landlock rules, preventing access to non-essential
	// files. Only recent versions of the kernel support landlock (5.13+),
	// but the landlock library will continue without error if the kernel
	// does not support it.
	allowedPaths := []landlock.PathOpt{
		landlock.PathAccess(llsyscall.AccessFSReadFile, configPath),
	}
	if logNormalFile {
		allowedPaths = append(allowedPaths,
			landlock.PathAccess(llsyscall.AccessFSWriteFile, logPath),
		)
	}

	err := landlock.V1.BestEffort().RestrictPaths(
		allowedPaths...,
	)
	if err != nil {
		log.Fatalf("error creating landlock rules: %v", err)
	}

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

	// Install seccomp filters to severely limit what egress-eddie is
	// allowed to do. The landlock rules plus the seccomp filters
	// will hopefully make it extremely difficult for an attacker to do
	// anything of value from the context of an egress-eddie process.
	numAllowedSyscalls, err := installSeccompFilters(logger, config.SelfDNSQueue != 0)
	if err != nil {
		logger.Error("error setting seccomp rules", zap.NamedError("error", err))
		return
	}
	logger.Info("applied seccomp filters", zap.Int("syscalls.allowed", numAllowedSyscalls))

	<-ctx.Done()
}
