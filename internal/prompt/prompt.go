// Package prompt handles the optional fzf interaction boundary.
package prompt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"
)

// MissingInputError is returned whenever required interactive values cannot be completed.
type MissingInputError struct {
	Fields []string
}

func (e *MissingInputError) Error() string {
	return fmt.Sprintf("missing required input(s): %s", strings.Join(e.Fields, ", "))
}

// CanPrompt reports whether both standard streams are interactive terminals.
func CanPrompt() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// Select chooses one value with the optional fzf executable.
func Select(ctx context.Context, label string, choices []string) (string, error) {
	values, err := selectValues(ctx, label, choices, false)
	if err != nil {
		return "", err
	}
	return values[0], nil
}

// SelectMany chooses one or more values using fzf's multi-select mode.
func SelectMany(ctx context.Context, label string, choices []string) ([]string, error) {
	values, err := selectValues(ctx, label, choices, true)
	if err != nil {
		return nil, fmt.Errorf("select %s: %w", label, err)
	}
	return values, nil
}

func selectValues(ctx context.Context, label string, choices []string, multiple bool) ([]string, error) {
	if len(choices) == 0 {
		return nil, errors.New("no values available for " + label)
	}
	command, err := exec.LookPath("fzf")
	if err != nil {
		return nil, err
	}
	args := []string{"--prompt=" + label + "> ", "--height=12", "--reverse"}
	if multiple {
		args = append(args, "--multi")
	}
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdin = strings.NewReader(strings.Join(choices, "\n") + "\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("select %s: %w", label, err)
	}
	values := strings.Fields(string(output))
	if len(values) == 0 {
		return nil, errors.New("no value selected for " + label)
	}
	return values, nil
}
