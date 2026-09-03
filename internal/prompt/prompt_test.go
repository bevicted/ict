package prompt

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

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
