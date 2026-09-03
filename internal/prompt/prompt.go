// Package prompt handles the optional fzf interaction boundary.
package prompt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

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

// SelectWithLoader starts fzf before loading its choices so its streaming input indicator is visible while waiting.
func SelectWithLoader(ctx context.Context, label string, load func(context.Context) ([]string, error)) (string, error) {
	values, err := selectLoadedValues(ctx, label, load, false)
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
	return selectLoadedValues(ctx, label, func(context.Context) ([]string, error) {
		return choices, nil
	}, multiple)
}

func selectLoadedValues(ctx context.Context, label string, load func(context.Context) ([]string, error), multiple bool) ([]string, error) {
	command, err := exec.LookPath("fzf")
	if err != nil {
		return nil, err
	}
	args := []string{"--prompt=" + label + "> ", "--height=12", "--reverse"}
	if multiple {
		args = append(args, "--multi")
	}
	loadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(loadCtx, command, args...)
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	type loadResult struct {
		err        error
		fromLoader bool
	}
	loaded := make(chan loadResult, 1)
	go func() {
		choices, loadErr := load(loadCtx)
		if loadErr == nil && len(choices) == 0 {
			loadErr = errors.New("no values available for " + label)
		}
		if loadErr != nil {
			loaded <- loadResult{err: loadErr, fromLoader: true}
			_ = stdin.Close()
			return
		}
		_, writeErr := io.WriteString(stdin, strings.Join(choices, "\n")+"\n")
		loaded <- loadResult{err: writeErr}
		_ = stdin.Close()
	}()

	commandDone := make(chan error, 1)
	go func() { commandDone <- cmd.Wait() }()

	var commandErr error
	select {
	case result := <-loaded:
		if result.fromLoader {
			cancel()
			_ = stdin.Close()
			<-commandDone
			return nil, result.err
		}
		commandErr = <-commandDone
		if result.err != nil && commandErr == nil {
			return nil, result.err
		}
	case commandErr = <-commandDone:
		select {
		case result := <-loaded:
			if result.fromLoader {
				return nil, result.err
			}
		default:
		}
	}
	cancel()
	_ = stdin.Close()
	if commandErr != nil {
		return nil, fmt.Errorf("select %s: %w", label, commandErr)
	}
	if output.Len() == 0 {
		return nil, errors.New("no value selected for " + label)
	}
	values := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(values) == 1 && values[0] == "" {
		return nil, errors.New("no value selected for " + label)
	}
	return values, nil
}
