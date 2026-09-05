package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/bevicted/ict/internal/cli"
)

func TestPrintParseUsageForMissingCommand(t *testing.T) {
	parsed, command, err := cli.Parse(nil)
	if err == nil {
		t.Fatal("Parse accepted a missing command")
	}
	if parsed != nil || command == nil {
		t.Fatalf("Parse returned context = %v, command = %v", parsed, command)
	}

	var parseErr *kong.ParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("Parse error type = %T, want *kong.ParseError", err)
	}
	var output strings.Builder
	parseErr.Context.Kong.Stdout = &output

	if err := printParseUsage(err); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Usage: ict <command>",
		"plan [flags]",
		"create [flags]",
		"destroy [flags]",
		"list (ls)",
		"config show [flags]",
		"config get <path> [flags]",
		"config set <path> <yaml-value> [flags]",
		"config edit [flags]",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("usage does not contain %q:\n%s", want, output.String())
		}
	}
}
