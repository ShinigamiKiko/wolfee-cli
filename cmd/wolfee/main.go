package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"sca-go/cli/internal/cli"
)

type exitCoder interface{ ExitCode() int }

func main() {

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := cli.Run(ctx, os.Args[1:])
	if err == nil {
		return
	}

	var ec exitCoder
	if errors.As(err, &ec) {
		fmt.Fprintf(os.Stderr, "wolfee: %s\n", err)
		os.Exit(ec.ExitCode())
	}
	fmt.Fprintf(os.Stderr, "wolfee: %s\n", err)
	os.Exit(1)
}
