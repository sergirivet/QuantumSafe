package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sergirivet/QuantumSafe/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = os.Stderr.WriteString("quantumsafe: " + err.Error() + "\n")
		os.Exit(1)
	}
}
