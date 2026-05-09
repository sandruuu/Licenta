package deviceidentity

import "testing"

func TestKeyNameForSID(t *testing.T) {
	if got := KeyNameForSID(" S-1-5-21-1000 "); got != "ZTNA_DeviceKey_S-1-5-21-1000" {
		t.Fatalf("KeyNameForSID() = %q", got)
	}
	if got := KeyNameForSID(" "); got != "" {
		t.Fatalf("KeyNameForSID(empty) = %q", got)
	}
}

func TestDeviceIDFromEKPublic(t *testing.T) {
	got, err := DeviceIDFromEKPublic([]byte("canonical-ek-public"))
	if err != nil {
		t.Fatalf("DeviceIDFromEKPublic returned error: %v", err)
	}
	const want = "17853f160f50c089d949974b28cc1e27cef3efee8a3aca15b9ec20771a03617a"
	if got != want {
		t.Fatalf("DeviceIDFromEKPublic() = %q, want %q", got, want)
	}
	if _, err := DeviceIDFromEKPublic(nil); err == nil {
		t.Fatalf("DeviceIDFromEKPublic accepted empty input")
	}
}
