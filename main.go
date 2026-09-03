package main

import (
	"context"
	"fmt"
	"os"

	"github.com/bevicted/ict/internal/cli"
)

func main() {
	parsed, command, err := cli.Parse(os.Args[1:])
	if err == nil {
		err = cli.Run(context.Background(), parsed, command)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
