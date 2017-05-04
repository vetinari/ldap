package ldap

import (
	"reflect"
	"testing"
)

// TestNewEntry tests that repeated calls to NewEntry return the same value with the same input
func TestNewEntry(t *testing.T) {
	dn := "testDN"
	attributes := map[string][]string{
		"alpha":   {"value"},
		"beta":    {"value"},
		"gamma":   {"value"},
		"delta":   {"value"},
		"epsilon": {"value"},
	}
	exectedEntry := NewEntry(dn, attributes)

	iteration := 0
	for {
		if iteration == 100 {
			break
		}
		testEntry := NewEntry(dn, attributes)
		if !reflect.DeepEqual(exectedEntry, testEntry) {
			t.Fatalf("consequent calls to NewEntry did not yield the same result:\n\texpected:\n\t%s\n\tgot:\n\t%s\n", exectedEntry, testEntry)
		}
		iteration = iteration + 1
	}
}

func TestGetAttributeValue(t *testing.T) {
	dn := "testDN"
	attributes := map[string][]string{
		"Alpha":   {"value"},
		"bEta":    {"value"},
		"gaMma":   {"value"},
		"delTa":   {"value"},
		"epsiLon": {"value"},
	}
	entry := NewEntry(dn, attributes)
	if entry.GetAttributeValue("Alpha") != "value" {
		t.Errorf("failed to get attribute in original case")
	}
	if entry.GetAttributeValue("alpha") != "value" {
		t.Errorf("failed to get attribute in changed case")
	}
}
