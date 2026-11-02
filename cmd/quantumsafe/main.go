package main

import (
	"context"
	"os"

	"github.com/sergirivet/QuantumSafe/internal/app"
)

func main() {
	if err := app.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = os.Stderr.WriteString("quantumsafe: " + err.Error() + "\n")
		os.Exit(1)
	}
}
