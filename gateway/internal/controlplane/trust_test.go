package controlplane

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestStringListFieldReadsRevokedSerials(t *testing.T) {
	response, err := structpb.NewStruct(map[string]interface{}{
		"revoked_serials": []interface{}{"111", " 222 ", ""},
	})
	if err != nil {
		t.Fatalf("build response: %v", err)
	}

	serials, err := stringListField(response, "revoked_serials", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSameSerialSet(t, serials, []string{"111", "222"})
}

func TestStringListFieldRejectsMalformedResponse(t *testing.T) {
	response, err := structpb.NewStruct(map[string]interface{}{
		"revoked_serials": "not-a-list",
	})
	if err != nil {
		t.Fatalf("build response: %v", err)
	}

	_, err = stringListField(response, "revoked_serials", true)
	if err == nil {
		t.Fatal("expected error for malformed revocation response")
	}
	if !strings.Contains(err.Error(), "must be a list") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertSameSerialSet(t *testing.T, got, expected []string) {
	t.Helper()

	if len(got) != len(expected) {
		t.Fatalf("unexpected serial count: got=%d expected=%d (got=%v)", len(got), len(expected), got)
	}

	expectedSet := make(map[string]struct{}, len(expected))
	for _, serial := range expected {
		expectedSet[serial] = struct{}{}
	}

	for _, serial := range got {
		if _, ok := expectedSet[serial]; !ok {
			t.Fatalf("unexpected serial %q in result %v", serial, got)
		}
	}
}
