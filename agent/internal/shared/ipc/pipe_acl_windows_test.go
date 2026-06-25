//go:build windows

package ipc

import (
	"strings"
	"testing"
)

func TestPipeSecurityDescriptorUsesExplicitSID(t *testing.T) {
	descriptor, err := PipeSecurityDescriptor(" S-1-5-21-1000 ")
	if err != nil {
		t.Fatalf("PipeSecurityDescriptor returned error: %v", err)
	}
	if !strings.Contains(descriptor, "(A;;GRGW;;;S-1-5-21-1000)") {
		t.Fatalf("descriptor does not include explicit SID: %q", descriptor)
	}
	if strings.Contains(descriptor, interactiveUserACE) {
		t.Fatalf("descriptor should not include Interactive Users when explicit SID is configured: %q", descriptor)
	}
}

func TestPipeSecurityDescriptorRejectsInvalidSID(t *testing.T) {
	if _, err := PipeSecurityDescriptor("not-a-sid"); err == nil {
		t.Fatal("PipeSecurityDescriptor accepted invalid SID")
	}
}
