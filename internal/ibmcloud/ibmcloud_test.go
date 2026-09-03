package ibmcloud

import (
	"context"
	"reflect"
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
