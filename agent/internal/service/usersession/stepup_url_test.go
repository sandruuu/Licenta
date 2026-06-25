package usersession

import "testing"

func TestValidStepUpURLRequiresTrustedHTTPSBrowserStepUpURL(t *testing.T) {
	manager := NewManager(Config{TrustedStepUpHosts: []string{"pdp.example.test"}}, Dependencies{})

	if !manager.validStepUpURL("https://pdp.example.test/verify/stepup-1") {
		t.Fatal("expected trusted PDP step-up URL to be accepted")
	}
	for _, raw := range []string{
		"http://pdp.example.test/verify/stepup-1",
		"https://evil.example.test/verify/stepup-1",
		"https://pdp.example.test/dashboard/",
	} {
		if manager.validStepUpURL(raw) {
			t.Fatalf("expected URL to be rejected: %s", raw)
		}
	}
}
