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
	if len(choices) == 0 {
		return "", errors.New("no values available for " + label)
	}
	command, err := exec.LookPath("fzf")
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, command, "--prompt="+label+"> ", "--height=12", "--reverse")
	cmd.Stdin = strings.NewReader(strings.Join(choices, "\n") + "\n")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("select %s: %w", label, err)
	}
	value := strings.TrimSpace(string(output))
	if value == "" {
		return "", errors.New("no value selected for " + label)
	}
	return value, nil
}
