package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/bevicted/ict/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	parsed, command, err := cli.Parse(os.Args[1:])
	if err == nil {
		err = cli.Run(ctx, parsed, command)
	}
	if err != nil {
		if usageErr := printParseUsage(err); usageErr != nil {
			fmt.Fprintln(os.Stderr, "error:", usageErr)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func printParseUsage(err error) error {
	var parseErr *kong.ParseError
	if !errors.As(err, &parseErr) || parseErr.Context == nil {
		return nil
	}
	if err := parseErr.Context.PrintUsage(false); err != nil {
		return fmt.Errorf("print usage: %w", err)
	}
	return nil
}
