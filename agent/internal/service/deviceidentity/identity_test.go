package deviceidentity

import "testing"

func TestKeyNameForDevice(t *testing.T) {
	if got := KeyNameForDevice(); got != "ZTNA_DeviceKey" {
		t.Fatalf("KeyNameForDevice() = %q", got)
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
