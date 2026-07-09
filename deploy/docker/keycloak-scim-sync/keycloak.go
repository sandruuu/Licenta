package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type keycloakClient struct {
	baseURL   string
	realm     string
	authRealm string
	clientID  string
	secret    string
	username  string
	password  string
	pageSize  int
	http      *http.Client
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

type keycloakUser struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Enabled   *bool  `json:"enabled"`
}

type keycloakGroup struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Path      string          `json:"path"`
	SubGroups []keycloakGroup `json:"subGroups"`
}

func (kc *keycloakClient) accessToken(ctx context.Context) (string, error) {
	form := url.Values{}
	form.Set("client_id", kc.clientID)
	if kc.secret != "" {
		form.Set("grant_type", "client_credentials")
		form.Set("client_secret", kc.secret)
	} else {
		form.Set("grant_type", "password")
		form.Set("username", kc.username)
		form.Set("password", kc.password)
	}

	var token tokenResponse
	if err := kc.doJSON(ctx, http.MethodPost, fmt.Sprintf("/realms/%s/protocol/openid-connect/token", url.PathEscape(kc.authRealm)), strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", "", &token); err != nil {
		return "", fmt.Errorf("get Keycloak token: %w", err)
	}
	if token.AccessToken == "" {
		return "", errors.New("Keycloak token response did not include access_token")
	}
	return token.AccessToken, nil
}

func (kc *keycloakClient) users(ctx context.Context, token string) ([]keycloakUser, error) {
	var all []keycloakUser
	for first := 0; ; first += kc.pageSize {
		var page []keycloakUser
		path := fmt.Sprintf("/admin/realms/%s/users?briefRepresentation=false&first=%d&max=%d", url.PathEscape(kc.realm), first, kc.pageSize)
		if err := kc.doJSON(ctx, http.MethodGet, path, nil, "", token, &page); err != nil {
			return nil, fmt.Errorf("list Keycloak users: %w", err)
		}
		all = append(all, page...)
		if len(page) < kc.pageSize {
			return all, nil
		}
	}
}

func (kc *keycloakClient) groups(ctx context.Context, token string) ([]keycloakGroup, error) {
	var all []keycloakGroup
	for first := 0; ; first += kc.pageSize {
		var page []keycloakGroup
		path := fmt.Sprintf("/admin/realms/%s/groups?briefRepresentation=false&first=%d&max=%d", url.PathEscape(kc.realm), first, kc.pageSize)
		if err := kc.doJSON(ctx, http.MethodGet, path, nil, "", token, &page); err != nil {
			return nil, fmt.Errorf("list Keycloak groups: %w", err)
		}
		all = append(all, page...)
		if len(page) < kc.pageSize {
			return all, nil
		}
	}
}

func (kc *keycloakClient) groupMembers(ctx context.Context, token, groupID string) ([]keycloakUser, error) {
	var all []keycloakUser
	for first := 0; ; first += kc.pageSize {
		var page []keycloakUser
		path := fmt.Sprintf("/admin/realms/%s/groups/%s/members?first=%d&max=%d", url.PathEscape(kc.realm), url.PathEscape(groupID), first, kc.pageSize)
		if err := kc.doJSON(ctx, http.MethodGet, path, nil, "", token, &page); err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < kc.pageSize {
			return all, nil
		}
	}
}

func (kc *keycloakClient) doJSON(ctx context.Context, method, path string, body io.Reader, contentType, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, kc.baseURL+path, body)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := kc.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, out)
}
