package transport

import (
	"encoding/json"
	"log"

	"github.com/go-webauthn/webauthn/webauthn"
)

// loadWebAuthnCredentials loads and deserialises all WebAuthn credentials for a user.
func (s *Server) loadWebAuthnCredentials(userID string) ([]webauthn.Credential, error) {
	dbCreds, err := s.pa.Store.GetWebAuthnCredentials(userID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(dbCreds))
	for _, dc := range dbCreds {
		credentialJSON := dc.CredentialJSON
		if s != nil && s.pa != nil && s.pa.Auth != nil && s.pa.Auth.Users != nil {
			plaintext, err := s.pa.Auth.Users.UnprotectMFAValue(credentialJSON)
			if err != nil {
				log.Printf("[WEBAUTHN] Could not decrypt credential %s: %v", dc.ID, err)
				continue
			}
			credentialJSON = plaintext
		}
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(credentialJSON), &c); err != nil {
			log.Printf("[WEBAUTHN] Corrupt credential %s: %v", dc.ID, err)
			continue
		}
		creds = append(creds, c)
	}
	return creds, nil
}
