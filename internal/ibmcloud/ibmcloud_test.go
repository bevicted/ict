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
