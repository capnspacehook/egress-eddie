package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	configPath   string
	debugLogs    bool
	logPath      string
	testConfig   bool
	printVersion bool
)

func init() {
	flag.StringVar(&configPath, "c", "egress-eddie.toml", "path of the config file")
	flag.BoolVar(&debugLogs, "d", false, "enable debug logging")
	flag.StringVar(&logPath, "l", "egress-eddie.log", "path to log to")
	flag.BoolVar(&testConfig, "t", false, "validate the config and exit")
	flag.BoolVar(&printVersion, "version", false, "print version and build information and exit")
}

func main() {
	flag.Parse()

	info, ok := debug.ReadBuildInfo()
	if !ok {
		log.Fatal("build information not found")
	}

	if printVersion {
		fmt.Println(info)
		os.Exit(0)
	}

	logCfg := zap.NewProductionConfig()
	logCfg.OutputPaths = []string{logPath}
	if debugLogs {
		logCfg.Level.SetLevel(zap.DebugLevel)
	}
	logCfg.EncoderConfig.TimeKey = "time"
	logCfg.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	logCfg.DisableCaller = true

	logger, err := logCfg.Build()
	if err != nil {
		log.Fatalf("error creating logger: %v", err)
	}

	for _, buildSetting := range info.Settings {
		if buildSetting.Key == "CGO_ENABLED" && buildSetting.Value != "0" {
			logger.Fatal("this binary was built with cgo and will not function as intended; rebuild with cgo disabled")
		}
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

	// Try and apply landlock rules, preventing access to non-essential
	// files. Only recent versions of the kernel support landlock (5.13+),
	// but we will ignroe errors if the kernel itself does not support it.
	// These rules can only apply when egress-eddie does not need to make
	// network connections, as currently it seems landlock does not support
	// networking.
	if config.SelfDNSQueue == 0 {
		var allowedPaths []landlock.PathOpt
		if logPath != "stdout" && logPath != "stderr" {
			allowedPaths = []landlock.PathOpt{
				landlock.PathAccess(llsyscall.AccessFSWriteFile, logPath),
			}
		}

		err = landlock.V1.RestrictPaths(
			allowedPaths...,
		)
		if err != nil {
			if !strings.HasPrefix(err.Error(), "missing kernel Landlock support") {
				logger.Fatal("error creating landlock rules", zap.NamedError("error", err))
			}
		}
		logger.Info("applied landlock rules")
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
	// The seccomp filters are installed after nfqueues are opened so
	// the related syscalls do not have to be allowed for the rest of
	// the process's lifetime.
	numAllowedSyscalls, err := installSeccompFilters(logger, config.SelfDNSQueue != 0)
	if err != nil {
		logger.Error("error setting seccomp rules", zap.NamedError("error", err))
		return
	}
	logger.Info("applied seccomp filters", zap.Int("syscalls.allowed", numAllowedSyscalls))

	<-ctx.Done()
}
