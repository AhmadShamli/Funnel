package models

import (
	"testing"
)

func TestPortEntryString(t *testing.T) {
	peSingle := PortEntry{Protocol: "tcp", StartPort: 80, EndPort: 80, IsRange: false}
	if peSingle.String() != "80/tcp" {
		t.Errorf("expected 80/tcp, got %s", peSingle.String())
	}

	peRange := PortEntry{Protocol: "tcp", StartPort: 8000, EndPort: 8010, IsRange: true}
	if peRange.String() != "8000-8010/tcp" {
		t.Errorf("expected 8000-8010/tcp, got %s", peRange.String())
	}

	peSingleRangeFlag := PortEntry{Protocol: "udp", StartPort: 53, EndPort: 53, IsRange: true}
	if peSingleRangeFlag.String() != "53/udp" {
		t.Errorf("expected 53/udp for single port range, got %s", peSingleRangeFlag.String())
	}
}

func TestGroupPortsIntoEntries(t *testing.T) {
	// Empty slice
	if entries := GroupPortsIntoEntries(nil); entries != nil {
		t.Errorf("expected nil for empty ports, got %+v", entries)
	}

	// Mixed single ports and ranges across protocols
	ports := []PortRule{
		{Protocol: "tcp", Port: 80},
		{Protocol: "tcp", Port: 443},
		{Protocol: "tcp", Port: 8000},
		{Protocol: "tcp", Port: 8001},
		{Protocol: "tcp", Port: 8002},
		{Protocol: "tcp", Port: 8005},
		{Protocol: "udp", Port: 53},
		{Protocol: "udp", Port: 5000},
		{Protocol: "udp", Port: 5001},
		{Protocol: "udp", Port: 5002},
	}

	entries := GroupPortsIntoEntries(ports)
	expectedStrings := []string{
		"80/tcp",
		"443/tcp",
		"8000-8002/tcp",
		"8005/tcp",
		"53/udp",
		"5000-5002/udp",
	}

	if len(entries) != len(expectedStrings) {
		t.Fatalf("expected %d entries, got %d: %+v", len(expectedStrings), len(entries), entries)
	}

	for i, exp := range expectedStrings {
		if entries[i].String() != exp {
			t.Errorf("entry %d: expected %s, got %s", i, exp, entries[i].String())
		}
	}

	// Test PortGroup.PortEntries()
	pg := &PortGroup{Ports: ports}
	pgEntries := pg.PortEntries()
	if len(pgEntries) != len(expectedStrings) {
		t.Errorf("expected %d PortGroup entries, got %d", len(expectedStrings), len(pgEntries))
	}

	// Test AccessGrant.PortEntries()
	grant := &AccessGrant{Ports: ports}
	grantEntries := grant.PortEntries()
	if len(grantEntries) != len(expectedStrings) {
		t.Errorf("expected %d AccessGrant entries, got %d", len(expectedStrings), len(grantEntries))
	}
}

func TestGroupPortsDeduplicationAndSorting(t *testing.T) {
	ports := []PortRule{
		{Protocol: "tcp", Port: 8080},
		{Protocol: "tcp", Port: 8080}, // duplicate
		{Protocol: "tcp", Port: 8079},
		{Protocol: "tcp", Port: 8081},
	}

	entries := GroupPortsIntoEntries(ports)
	if len(entries) != 1 {
		t.Fatalf("expected 1 range entry, got %d: %+v", len(entries), entries)
	}
	if entries[0].String() != "8079-8081/tcp" {
		t.Errorf("expected 8079-8081/tcp, got %s", entries[0].String())
	}
	if !entries[0].IsRange {
		t.Errorf("expected IsRange=true")
	}
}
