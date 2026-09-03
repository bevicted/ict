package prompt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

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
		deadline := time.Now().Add(time.Second)
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
	fzf := filepath.Join(bin, "fzf")
	if err := os.WriteFile(fzf, []byte("#!/bin/sh\nIFS= read -r value\nwhile :; do :; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	_, err := SelectWithLoader(context.Background(), "resource group", func(context.Context) ([]string, error) {
		return nil, errors.New("load failed")
	})
	if err == nil || err.Error() != "load failed" {
		t.Fatalf("loading error = %v", err)
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
