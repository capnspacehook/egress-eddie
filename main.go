package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"go.uber.org/zap"
)

var configPath string

func init() {
	flag.StringVar(&configPath, "c", "egress-eddie.toml", "path of the config file")
}

func main() {
	flag.Parse()

	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("error creating logger: %v", err)
	}

	config, err := ParseConfig(configPath)
	if err != nil {
		logger.Fatal("error parsing config", zap.String("error", err.Error()))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	filters, err := StartFilters(ctx, logger, config)
	if err != nil {
		logger.Fatal("error starting filters", zap.String("error", err.Error()))
	}
	logger.Info("started filtering")

	<-ctx.Done()

	logger.Info("stopping filters")
	filters.Stop()
}
