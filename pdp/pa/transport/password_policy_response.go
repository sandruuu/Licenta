package transport

import (
	"errors"
	"net/http"

	paauth "pdp/pa/auth"
)

func writePasswordPolicyError(w http.ResponseWriter, status int, err error) bool {
	var policyErr *paauth.PasswordPolicyError
	if !errors.As(err, &policyErr) {
		return false
	}
	writeJSON(w, status, map[string]any{
		"error":                 policyErr.Error(),
		"password_requirements": policyErr.Requirements,
	})
	return true
}
