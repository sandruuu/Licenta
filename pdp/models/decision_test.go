package models

import "testing"

func TestNormalizePolicyActionAcceptsOnlyCanonicalValues(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "allow", in: "allow", want: DecisionAllow, ok: true},
		{name: "deny", in: "deny", want: DecisionDeny, ok: true},
		{name: "step up required", in: "step_up_required", want: DecisionStepUpRequired, ok: true},
		{name: "empty rejected", in: "", ok: false},
		{name: "unknown rejected", in: "custom_action", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NormalizePolicyAction(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("NormalizePolicyAction(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}
