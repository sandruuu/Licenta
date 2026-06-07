package transport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderEnrollmentPageShowsDirectoryMismatchAsAlert(t *testing.T) {
	recorder := httptest.NewRecorder()

	renderEnrollmentPage(recorder, "Enroll device", "Email does not match any organization directory.", "laura@example.test", true)

	body := recorder.Body.String()
	for _, want := range []string{
		`class="page-alert" role="alert"`,
		`Email does not match any organization directory.`,
		`stroke-width="2.4"`,
		`<circle cx="12" cy="12" r="10"`,
		`<path d="M12 8v4"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("rendered page missing %q: %s", want, body)
		}
	}
}

func TestRenderEnrollmentPageShowsCancelledMark(t *testing.T) {
	recorder := httptest.NewRecorder()

	renderEnrollmentPage(recorder, "Enrollment cancelled", "You can close this tab and go back to the TRUSTAgent app.", "", false)

	body := recorder.Body.String()
	for _, want := range []string{
		`class="cancel-mark"`,
		`<circle class="cancel-ring" pathLength="1" cx="36" cy="36" r="25"`,
		`class="cancel-cross-first" pathLength="1" d="M26 26l20 20"`,
		`class="cancel-cross-second" pathLength="1" d="M46 26L26 46"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("rendered page missing %q: %s", want, body)
		}
	}
}

func TestRenderEnrollmentPageShowsSuccessMark(t *testing.T) {
	recorder := httptest.NewRecorder()

	renderEnrollmentPage(recorder, "Device enrolled", "You can return to TrustAgent.", "", false)

	body := recorder.Body.String()
	for _, want := range []string{
		`class="completion-mark"`,
		`class="completion-ring"`,
		`class="completion-check" pathLength="1" d="M20 39l13 13 25-31"`,
		`You can close this tab and go back to the TRUSTAgent app.`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("rendered page missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, `class="cancel-mark"`) {
		t.Fatalf("success page should not show cancel mark: %s", body)
	}
}

func TestRenderEnrollmentPageShowsUnavailableMark(t *testing.T) {
	recorder := httptest.NewRecorder()

	renderEnrollmentPage(recorder, "Enrollment unavailable", "The enrollment session was not found or has expired.", "", false)

	body := recorder.Body.String()
	for _, want := range []string{
		`class="cancel-mark"`,
		`<circle class="cancel-ring" pathLength="1" cx="36" cy="36" r="25"`,
		`class="cancel-cross-first" pathLength="1" d="M26 26l20 20"`,
		`class="cancel-cross-second" pathLength="1" d="M46 26L26 46"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("rendered page missing %q: %s", want, body)
		}
	}
}

func TestRenderEnrollmentPageShowsVerificationFailureMarks(t *testing.T) {
	for _, title := range []string{
		"Verification unavailable",
		"Verification expired",
		"Authentication unavailable",
		"Authentication expired",
	} {
		t.Run(title, func(t *testing.T) {
			recorder := httptest.NewRecorder()

			renderEnrollmentPage(recorder, title, "Try again.", "", false)

			body := recorder.Body.String()
			for _, want := range []string{
				`class="cancel-mark"`,
				`class="cancel-cross-first" pathLength="1" d="M26 26l20 20"`,
				`class="cancel-cross-second" pathLength="1" d="M46 26L26 46"`,
			} {
				if !strings.Contains(body, want) {
					t.Fatalf("rendered page missing %q: %s", want, body)
				}
			}
			if strings.Contains(body, `class="completion-mark"`) {
				t.Fatalf("failure page should not show completion mark: %s", body)
			}
		})
	}
}

func TestRenderEnrollmentPageShowsDeniedMark(t *testing.T) {
	recorder := httptest.NewRecorder()

	renderEnrollmentPage(recorder, "Enrollment denied", "Authentication failed or the enrollment session was denied.", "", false)

	body := recorder.Body.String()
	for _, want := range []string{
		`class="cancel-mark"`,
		`class="cancel-cross-first" pathLength="1" d="M26 26l20 20"`,
		`class="cancel-cross-second" pathLength="1" d="M46 26L26 46"`,
		`.cancel-cross-second`,
		`animation:completionCheck .3s ease-out .88s forwards`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("rendered page missing %q: %s", want, body)
		}
	}
}

func TestRedirectBrowserCancelledUsesSeeOther(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://localhost:8443/browser/enroll/erq_test", nil)
	recorder := httptest.NewRecorder()

	redirectBrowserCancelled(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
	}
	if got, want := recorder.Header().Get("Location"), "/browser/enroll/erq_test?cancelled=1"; got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}
