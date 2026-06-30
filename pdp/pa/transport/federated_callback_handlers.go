package transport

import (
	"log"
	"net/http"
)

// federatedCallbackURL returns the PA callback URL registered at the external IAM.
func (s *Server) federatedCallbackURL() string {
	return s.appConfig().Public.FederatedCallbackURL
}

// handleFederatedCallback receives the authorization code from the external IAM
// after browser authentication. The code is consumed by the active browser flow:
// device enrollment, agent user login, or step-up reauthentication.
func (s *Server) handleFederatedCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errParam := r.URL.Query().Get("error")

	if errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		log.Printf("[FEDERATION] External IdP returned error: %s - %s", errParam, errDesc)
		http.Error(w, "External IdP error: "+errParam+": "+errDesc, http.StatusBadRequest)
		return
	}

	if code == "" || state == "" {
		http.Error(w, "Missing code or state parameter", http.StatusBadRequest)
		return
	}
	if s.handleEnrollmentFederatedCallback(w, r, code, state) {
		return
	}
	if s.handleAgentSessionFederatedCallback(w, r, code, state) {
		return
	}
	if s.handleStepUpFederatedCallback(w, r, code, state) {
		return
	}

	http.Error(w, "Unknown or expired federation session", http.StatusBadRequest)
}
