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
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	egresseddie "github.com/capnspacehook/egress-eddie"
)

func usage() {
	fmt.Fprintf(os.Stderr, `
Egress Eddie filters arbitrary outbound network traffic by hostname.

	eddie-eddie [flags]
	
Egress Eddie filters DNS traffic and only allows requests and replies to
specified hostnames. It then caches the IP addresses from allowed DNS replies
and only allows traffic to go to them.

Egress Eddie requires nftables/iptables rules to be set to function correctly;
it will not modify firewall rules itself. For more information on how to
correctly configure iptables to work with Egress Eddie and how to configure
Egress Eddie itself see the GitHub link below.

Egress Eddie accepts the following flags:

`[1:])
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `

For more information, see https://github.com/capnspacehook/egress-eddie.
`[1:])
}

func main() {
	flag.Usage = usage
	configPath := flag.String("c", "egress-eddie.toml", "path of the config file")
	debugLogs := flag.Bool("d", false, "enable debug logging")
	logFullDNSPackets := flag.Bool("f", false, "enable full DNS packet logging")
	logPath := flag.String("l", "stdout", "path to log to")
	validateConfig := flag.Bool("t", false, "validate the config and exit")
	printVersion := flag.Bool("version", false, "print version and build information and exit")
	flag.Parse()

	info, ok := debug.ReadBuildInfo()
	if !ok {
		log.Fatal("build information not found")
	}

	if *printVersion {
		printVersionInfo(info)
		os.Exit(0)
	}

	logCfg := zap.NewProductionConfig()
	logCfg.OutputPaths = []string{*logPath}
	if *debugLogs {
		logCfg.Level.SetLevel(zap.DebugLevel)
	}
	logCfg.EncoderConfig.TimeKey = "time"
	logCfg.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	logCfg.DisableCaller = true

	logger, err := logCfg.Build()
	if err != nil {
		log.Fatalf("error creating logger: %v", err)
	}

	var versionFields []zap.Field
	versionFields = append(versionFields, zap.String("version", version))
	for _, buildSetting := range info.Settings {
		if buildSetting.Key == "vcs.revision" {
			versionFields = append(versionFields, zap.String("commit", buildSetting.Value))
		}
		if buildSetting.Key == "CGO_ENABLED" && buildSetting.Value != "0" {
			logger.Fatal("this binary was built with cgo and will not function as intended; rebuild with cgo disabled")
		}
	}
	logger.Info("starting Egress Eddie", versionFields...)

	config, err := egresseddie.ParseConfig(*configPath)
	if *validateConfig {
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
	// but we will ignore errors if the kernel itself does not support it.
	// These rules can only be applied when egress-eddie does not need to make
	// network connections, as currently it seems landlock does not support
	// networking.
	needsNetworking := config.SelfDNSQueue.IPv4 != 0 || config.SelfDNSQueue.IPv6 != 0
	if !needsNetworking {
		var allowedPaths []landlock.PathOpt
		if *logPath != "stdout" && *logPath != "stderr" {
			allowedPaths = []landlock.PathOpt{
				landlock.PathAccess(llsyscall.AccessFSWriteFile, *logPath),
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

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	filters, err := egresseddie.CreateFilters(ctx, logger, config, *logFullDNSPackets)
	if err != nil {
		logger.Fatal("error starting filters", zap.NamedError("error", err))
	}

	defer func() {
		cancel()
		logger.Info("stopping filters")
		filters.Stop()
	}()

	// Install seccomp filters to severely limit what egress-eddie is
	// allowed to do. The landlock rules plus the seccomp filters
	// should make it extremely difficult for an attacker to do
	// anything of value from the context of an egress-eddie process.
	// The seccomp filters are installed after nfqueues are opened so
	// the related syscalls do not have to be allowed for the rest of
	// the process's lifetime.
	numAllowedSyscalls, err := installSeccompFilters(logger, needsNetworking)
	if err != nil {
		logger.Error("error setting seccomp rules", zap.NamedError("error", err))
		return
	}
	logger.Info("applied seccomp filters", zap.Int("syscalls.allowed", numAllowedSyscalls))

	// Start filters now that seccomp filters have been applied
	filters.Start()
	logger.Info("started filtering")

	<-ctx.Done()
}
