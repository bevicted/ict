package prompt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestConfirmAcceptsOnlyLiteralYes(t *testing.T) {
	for _, test := range []struct {
		input string
		want  bool
	}{
		{input: "yes\n", want: true},
		{input: "Yes\n", want: false},
		{input: "yes please\n", want: false},
	} {
		var output bytes.Buffer
		got, err := Confirm(strings.NewReader(test.input), &output)
		if err != nil || got != test.want || !strings.Contains(output.String(), "Enter a value") {
			t.Fatalf("Confirm(%q) = %t, %v, %q", test.input, got, err, output.String())
		}
	}
}

func TestConfirmReportsInputFailures(t *testing.T) {
	for _, input := range []string{"", "yes"} {
		if _, err := Confirm(strings.NewReader(input), io.Discard); err == nil {
			t.Fatalf("Confirm(%q) succeeded", input)
		}
	}
}

func TestSelectWithLoaderStartsFzfBeforeLoading(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(bin, "fzf-started")
	fzf := filepath.Join(bin, "fzf")
	script := "#!/bin/sh\n: > \"$FZF_STARTED\"\nIFS= read -r value\nprintf '%s\\n' \"$value\"\n"
	if err := os.WriteFile(fzf, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("FZF_STARTED", marker)

	value, err := SelectWithLoader(context.Background(), "resource group", func(context.Context) ([]string, error) {
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(marker); err == nil {
				return []string{"group loaded later"}, nil
			}
			if time.Now().After(deadline) {
				return nil, errors.New("fzf did not start before loading choices")
			}
			time.Sleep(time.Millisecond)
		}
	})
	if err != nil || value != "group loaded later" {
		t.Fatalf("selected value = %q, %v", value, err)
	}
}

func TestSelectWithLoaderReturnsLoadingError(t *testing.T) {
	bin := t.TempDir()
	started := filepath.Join(bin, "fzf-started")
	interrupted := filepath.Join(bin, "fzf-interrupted")
	fzf := filepath.Join(bin, "fzf")
	script := "#!/bin/sh\ntrap ': > \"$FZF_INTERRUPTED\"; exit 130' INT\n: > \"$FZF_STARTED\"\nIFS= read -r value\nwhile :; do :; done\n"
	if err := os.WriteFile(fzf, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("FZF_STARTED", started)
	t.Setenv("FZF_INTERRUPTED", interrupted)

	_, err := SelectWithLoader(context.Background(), "resource group", func(context.Context) ([]string, error) {
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(started); err == nil {
				return nil, errors.New("load failed")
			}
			if time.Now().After(deadline) {
				return nil, errors.New("fzf did not start before loading choices")
			}
			time.Sleep(time.Millisecond)
		}
	})
	if err == nil || err.Error() != "load failed" {
		t.Fatalf("loading error = %v", err)
	}
	if _, err := os.Stat(interrupted); err != nil {
		t.Fatalf("fzf did not receive a graceful interrupt: %v", err)
	}
}

func TestSelectionsPreserveWhitespace(t *testing.T) {
	bin := t.TempDir()
	fzf := filepath.Join(bin, "fzf")
	script := "#!/bin/sh\ncase \"$*\" in *--multi*) while IFS= read -r value; do printf '%s\\n' \"$value\"; done ;; *) IFS= read -r value; printf '%s\\n' \"$value\" ;; esac\n"
	if err := os.WriteFile(fzf, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	value, err := Select(context.Background(), "resource group", []string{"group with spaces"})
	if err != nil || value != "group with spaces" {
		t.Fatalf("selected value = %q, %v", value, err)
	}
	values, err := SelectMany(context.Background(), "resource groups", []string{"first group", "second group"})
	if err != nil || !reflect.DeepEqual(values, []string{"first group", "second group"}) {
		t.Fatalf("selected values = %#v, %v", values, err)
	}
}
