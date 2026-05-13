package transport

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

// handleOIDCToken is the OIDC Token Endpoint.
// The gateway calls this backend-to-backend to exchange an authorization code for tokens.
//
// POST /auth/token
// Content-Type: application/x-www-form-urlencoded (or application/json)
// Body: client_id, client_secret, grant_type=authorization_code, code, redirect_uri
//
// Response: { "access_token": "jwt...", "token_type": "Bearer", "expires_in": 3600, "id_token": "jwt..." }
func (s *Server) handleOIDCToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Support both form-encoded and JSON
	var clientID, clientSecret, grantType, code, redirectURI, codeVerifier, refreshTokenParam string

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var req struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
			GrantType    string `json:"grant_type"`
			Code         string `json:"code"`
			RedirectURI  string `json:"redirect_uri"`
			CodeVerifier string `json:"code_verifier"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		clientID = req.ClientID
		clientSecret = req.ClientSecret
		grantType = req.GrantType
		code = req.Code
		redirectURI = req.RedirectURI
		codeVerifier = req.CodeVerifier
		refreshTokenParam = req.RefreshToken
	} else {
		// application/x-www-form-urlencoded
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form data"})
			return
		}
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
		grantType = r.FormValue("grant_type")
		code = r.FormValue("code")
		redirectURI = r.FormValue("redirect_uri")
		codeVerifier = r.FormValue("code_verifier")
		refreshTokenParam = r.FormValue("refresh_token")
	}

	// Validate grant_type
	if grantType != "authorization_code" && grantType != "refresh_token" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":             "unsupported_grant_type",
			"error_description": "Only authorization_code and refresh_token grant types are supported",
		})
		return
	}

	// ── Handle refresh_token grant ──
	if grantType == "refresh_token" {
		if refreshTokenParam == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "refresh_token is required",
			})
			return
		}

		newRT, newToken, err := s.pa.Auth.OIDC.RefreshAccessToken(refreshTokenParam, clientID, clientSecret)
		if err != nil {
			log.Printf("[OIDC] Refresh token failed: %v", err)
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":             "invalid_grant",
				"error_description": err.Error(),
			})
			return
		}

		// Issue a new JWT for this user, preserving device binding and MFA state.
		token, err := s.pa.Auth.JWT.GenerateAuthToken(newRT.UserID, newRT.Username, newRT.Role, newRT.DeviceID, "", newRT.MFADone)
		if err != nil {
			log.Printf("[OIDC] Failed to issue token during refresh: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"error":             "server_error",
				"error_description": "failed to issue access token",
			})
			return
		}

		s.pa.Audit.LogEvent("oidc_token_refresh", newRT.UserID, newRT.Username,
			r.RemoteAddr, "", "", "Token refresh for "+clientID, true)

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"access_token":  token,
			"token_type":    "Bearer",
			"expires_in":    int(s.pa.Cfg.JWTExpiry.Seconds()),
			"refresh_token": newToken,
			"user_id":       newRT.UserID,
			"username":      newRT.Username,
			"role":          newRT.Role,
			"device_id":     newRT.DeviceID,
		})
		return
	}

	// Validate required params
	if clientID == "" || code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "client_id and code are required",
		})
		return
	}

	// Exchange the authorization code
	authCode, refreshToken, err := s.pa.Auth.OIDC.ExchangeCode(code, clientID, clientSecret, redirectURI, codeVerifier)
	if err != nil {
		log.Printf("[OIDC] Token exchange failed: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
		return
	}

	// The auth_token was already issued during login. Return it as the access_token.
	// Generate a fresh id_token that includes the OIDC nonce for replay protection.
	log.Printf("[OIDC] Token exchange successful: user=%s client=%s", authCode.Username, clientID)

	idToken := authCode.AuthToken
	if authCode.Nonce != "" {
		// Issue a new JWT with nonce embedded (OIDC Core 1.0 §3.1.2.1).
		// Preserve the MFADone status from the original auth token.
		originalClaims, parseErr := s.pa.Auth.ParseToken(authCode.AuthToken)
		mfaDone := parseErr == nil && originalClaims.MFADone
		freshToken, err := s.pa.Auth.JWT.GenerateAuthToken(
			authCode.UserID, authCode.Username, authCode.Role, authCode.DeviceID, authCode.Nonce, mfaDone,
		)
		if err == nil {
			idToken = freshToken
		}
	}

	s.pa.Audit.LogEvent("oidc_token_exchange", authCode.UserID, authCode.Username,
		r.RemoteAddr, "", "", "Token exchange for "+clientID, true)

	response := map[string]interface{}{
		"access_token":  authCode.AuthToken,
		"token_type":    "Bearer",
		"expires_in":    int(s.pa.Cfg.JWTExpiry.Seconds()),
		"id_token":      idToken,
		"refresh_token": refreshToken,
		"user_id":       authCode.UserID,
		"username":      authCode.Username,
		"role":          authCode.Role,
		"device_id":     authCode.DeviceID,
	}
	if authCode.Nonce != "" {
		response["nonce"] = authCode.Nonce
	}

	writeJSON(w, http.StatusOK, response)
}
