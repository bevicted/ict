package ibmcloud

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeRunner struct {
	output []byte
	args   []string
}

func (f *fakeRunner) Run(_ context.Context, _ []string, _ string, args ...string) ([]byte, error) {
	f.args = args
	return f.output, nil
}

func TestCommandRunnerReportsIBMCloudOutputOnFailure(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "ibmcloud")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf 'authentication failed\\n' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)

	_, err := (CommandRunner{}).Run(context.Background(), os.Environ(), "ibmcloud")
	if err == nil {
		t.Fatal("Run succeeded, want command failure")
	}
	for _, want := range []string{"run ibmcloud: exit status 1", "authentication failed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestResourceGroupsUseOnlyTopLevelNames(t *testing.T) {
	fake := &fakeRunner{output: []byte(`[
		{"name":"group with spaces","id":"unrelated identifier","metadata":{"name":"nested group"}},
		{"id":"identifier only","label":"arbitrary string"},
		{"name":"another group"}
	]`)}
	values, err := (Discovery{Runner: fake}).ResourceGroups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"another group", "group with spaces"}; !reflect.DeepEqual(values, want) {
		t.Fatalf("resource groups = %#v, want %#v", values, want)
	}
	if want := []string{"resource", "groups", "--output", "json", "-q"}; !reflect.DeepEqual(fake.args, want) {
		t.Fatalf("resource group args = %#v, want %#v", fake.args, want)
	}
}

func TestVersionsDecodeStructuredJSON(t *testing.T) {
	tests := []struct {
		platform string
		output   string
		want     []string
		service  string
	}{
		{
			platform: "kubernetes",
			output:   `{"kubernetes":[{"major":1,"minor":36,"patch":4},{"major":1,"minor":37,"patch":0}]}`,
			want:     []string{"1.36.4", "1.37.0"},
			service:  "Kubernetes",
		},
		{
			platform: "openshift",
			output:   `{"openshift":[{"major":4,"minor":21,"patch":29},{"major":5,"minor":0,"patch":0}]}`,
			want:     []string{"4.21.29_openshift", "5.0.0_openshift"},
			service:  "OpenShift",
		},
	}
	for _, test := range tests {
		t.Run(test.platform, func(t *testing.T) {
			fake := &fakeRunner{output: []byte(test.output)}
			values, err := (Discovery{Runner: fake}).Versions(context.Background(), test.platform)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(values, test.want) {
				t.Fatalf("versions = %#v, want %#v", values, test.want)
			}
			wantArgs := []string{"ks", "versions", "--show-version", test.service, "--output", "json", "-q"}
			if !reflect.DeepEqual(fake.args, wantArgs) {
				t.Fatalf("version args = %#v, want %#v", fake.args, wantArgs)
			}
		})
	}
}

func TestClassicDiscoveryUsesClassicCommands(t *testing.T) {
	fake := &fakeRunner{output: []byte(`[{"name":"dal10"},{"name":"not-a-datacenter"}]`)}
	values, err := (Discovery{Runner: fake}).ClassicDatacenters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"dal10"}; !reflect.DeepEqual(values, want) {
		t.Fatalf("datacenters = %#v, want %#v", values, want)
	}
	if want := []string{"ks", "locations", "--provider", "classic", "--output", "json", "-q"}; !reflect.DeepEqual(fake.args, want) {
		t.Fatalf("datacenter args = %#v, want %#v", fake.args, want)
	}

	fake.output = []byte(`[{"name":"bx2.2x8"},{"name":"unsupported"}]`)
	values, err = (Discovery{Runner: fake}).ClassicMachineTypes(context.Background(), "dal10")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"bx2.2x8"}; !reflect.DeepEqual(values, want) {
		t.Fatalf("machine types = %#v, want %#v", values, want)
	}
	if want := []string{"ks", "flavor", "ls", "--zone", "dal10", "--provider", "classic", "--output", "json", "-q"}; !reflect.DeepEqual(fake.args, want) {
		t.Fatalf("machine type args = %#v, want %#v", fake.args, want)
	}
}

func TestSatelliteDiscoveryUsesJSONCommands(t *testing.T) {
	fake := &fakeRunner{output: []byte(`[{"name":"us-south"},{"name":"not a location"}]`)}
	values, err := (Discovery{Runner: fake}).SatelliteManagedFrom(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"us-south"}; !reflect.DeepEqual(values, want) {
		t.Fatalf("management locations = %#v, want %#v", values, want)
	}
	if want := []string{"ks", "locations", "--provider", "satellite", "--output", "json", "-q"}; !reflect.DeepEqual(fake.args, want) {
		t.Fatalf("management location args = %#v, want %#v", fake.args, want)
	}

	fake.output = []byte(`[{"name":"rhel-8-synthetic"},{"name":"other-image"}]`)
	values, err = (Discovery{Runner: fake}).SatelliteHostImages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"rhel-8-synthetic"}; !reflect.DeepEqual(values, want) {
		t.Fatalf("host images = %#v, want %#v", values, want)
	}
	if want := []string{"is", "images", "--visibility", "public", "--output", "json"}; !reflect.DeepEqual(fake.args, want) {
		t.Fatalf("host image args = %#v, want %#v", fake.args, want)
	}

	fake.output = []byte(`[{"name":"bx2-4x16"},{"name":"unsupported"}]`)
	values, err = (Discovery{Runner: fake}).SatelliteHostProfiles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"bx2-4x16"}; !reflect.DeepEqual(values, want) {
		t.Fatalf("host profiles = %#v, want %#v", values, want)
	}
}

func TestDiscoveryDecodesAndNormalizesJSON(t *testing.T) {
	fake := &fakeRunner{output: []byte(`[{"name":"us-south-2"},{"nested":{"name":"us-south-1"}},{"name":"not-a-zone"}]`)}
	values, err := (Discovery{Runner: fake}).Zones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"us-south-1", "us-south-2"}; !reflect.DeepEqual(values, want) {
		t.Fatalf("zones = %#v, want %#v", values, want)
	}
	if got := fake.args[:2]; !reflect.DeepEqual(got, []string{"ks", "locations"}) {
		t.Fatalf("args = %#v", fake.args)
	}
}
