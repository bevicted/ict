package cli

import "testing"

func TestKongParsesICTEnvironment(t *testing.T) {
	t.Setenv("ICT_TARGET", "example")
	t.Setenv("ICT_PROVIDER", "vpc-gen2")
	t.Setenv("ICT_PLATFORM", "kubernetes")
	t.Setenv("ICT_VERSION", "1.31.4")
	t.Setenv("ICT_RESOURCE_GROUP", "fixture-group")
	t.Setenv("ICT_ZONE", "us-south-1")
	t.Setenv("ICT_FLAVOR", "bx2.2x8")
	parsed, command, err := Parse([]string{"plan", "--config", "config.yaml", "--name", "fixture-cluster"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "plan" || command.Plan.Target != "example" || command.Plan.Provider != "vpc-gen2" || command.Plan.Zone != "us-south-1" {
		t.Fatalf("parsed command = %q, plan = %#v", parsed.Command(), command.Plan)
	}
}

func TestKongParsesClassicInputs(t *testing.T) {
	parsed, command, err := Parse([]string{"plan", "--config", "config.yaml", "--target", "example", "--provider", "classic", "--platform", "openshift", "--version", "1.31.4", "--resource-group", "fixture-group", "--datacenter", "dal10", "--machine-type", "bx2.2x8", "--public-vlan-id", "12345", "--private-vlan-id", "67890"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Command() != "plan" || command.Plan.Provider != "classic" || command.Plan.Datacenter != "dal10" || command.Plan.PrivateVLANID != "67890" {
		t.Fatalf("parsed classic command = %q, plan = %#v", parsed.Command(), command.Plan)
	}
}

func TestDestroyRejectsReplacementInputs(t *testing.T) {
	_, _, err := Parse([]string{"destroy", "--name", "replacement"})
	if err == nil {
		t.Fatal("destroy accepted replacement input")
	}
}
