package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultKeycloakBaseURL = "http://keycloak:8080"
	defaultKeycloakRealm   = "trustcloud-lab"
	defaultPDPBaseURL      = "https://pdp:8443"
	defaultPageSize        = 100
)

type config struct {
	KeycloakBaseURL      string
	KeycloakRealm        string
	KeycloakAuthRealm    string
	KeycloakClientID     string
	KeycloakClientSecret string
	KeycloakUsername     string
	KeycloakPassword     string
	PDPBaseURL           string
	PDPSCIMBaseURL       string
	PDPOrganizationID    string
	PDPSCIMToken         string
	PDPTLSSkipVerify     bool
	SyncInterval         time.Duration
	SyncOnce             bool
	DisableMissingUsers  bool
	DeleteMissingGroups  bool
	SkipServiceAccounts  bool
	PageSize             int
}

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

type scimClient struct {
	baseURL string
	token   string
	http    *http.Client
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

type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type scimMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

type scimUser struct {
	Schemas     []string    `json:"schemas,omitempty"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Active      *bool       `json:"active,omitempty"`
	Emails      []scimEmail `json:"emails,omitempty"`
}

type scimGroup struct {
	Schemas     []string     `json:"schemas,omitempty"`
	ID          string       `json:"id,omitempty"`
	ExternalID  string       `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName,omitempty"`
	Members     []scimMember `json:"members,omitempty"`
}

type scimListResponse[T any] struct {
	Resources []T `json:"Resources"`
}

type syncStats struct {
	UsersUpserted       int
	GroupsUpserted      int
	UsersDeprovisioned  int
	GroupsDeprovisioned int
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("[KEYCLOAK-SCIM] Invalid config: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.PDPTLSSkipVerify}, //nolint:gosec // local lab connector supports self-signed PDP TLS.
		},
	}
	kc := &keycloakClient{
		baseURL:   cfg.KeycloakBaseURL,
		realm:     cfg.KeycloakRealm,
		authRealm: cfg.KeycloakAuthRealm,
		clientID:  cfg.KeycloakClientID,
		secret:    cfg.KeycloakClientSecret,
		username:  cfg.KeycloakUsername,
		password:  cfg.KeycloakPassword,
		pageSize:  cfg.PageSize,
		http:      httpClient,
	}
	scim := &scimClient{
		baseURL: cfg.PDPSCIMBaseURL,
		token:   cfg.PDPSCIMToken,
		http:    httpClient,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	run := func() {
		start := time.Now()
		stats, err := syncDirectory(ctx, cfg, kc, scim)
		if err != nil {
			log.Printf("[KEYCLOAK-SCIM] Sync failed: %v", err)
			return
		}
		log.Printf("[KEYCLOAK-SCIM] Sync completed in %s: users=%d groups=%d disabled_missing_users=%d deleted_missing_groups=%d",
			time.Since(start).Round(time.Millisecond), stats.UsersUpserted, stats.GroupsUpserted, stats.UsersDeprovisioned, stats.GroupsDeprovisioned)
	}

	run()
	if cfg.SyncOnce {
		return
	}

	ticker := time.NewTicker(cfg.SyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("[KEYCLOAK-SCIM] Stopping")
			return
		case <-ticker.C:
			run()
		}
	}
}

func loadConfig() (config, error) {
	cfg := config{
		KeycloakBaseURL:     strings.TrimRight(env("KEYCLOAK_BASE_URL", defaultKeycloakBaseURL), "/"),
		KeycloakRealm:       env("KEYCLOAK_REALM", defaultKeycloakRealm),
		KeycloakClientID:    env("KEYCLOAK_CLIENT_ID", "admin-cli"),
		KeycloakUsername:    env("KEYCLOAK_ADMIN_USERNAME", env("KEYCLOAK_ADMIN", "admin")),
		KeycloakPassword:    env("KEYCLOAK_ADMIN_PASSWORD", "admin"),
		PDPBaseURL:          strings.TrimRight(env("PDP_BASE_URL", defaultPDPBaseURL), "/"),
		PDPOrganizationID:   strings.TrimSpace(os.Getenv("PDP_ORGANIZATION_ID")),
		PDPSCIMToken:        strings.TrimSpace(os.Getenv("PDP_SCIM_TOKEN")),
		PDPTLSSkipVerify:    envBool("PDP_TLS_SKIP_VERIFY", true),
		SyncInterval:        envDuration("SYNC_INTERVAL", 60*time.Second),
		SyncOnce:            envBool("SYNC_ONCE", false),
		DisableMissingUsers: envBool("DISABLE_MISSING_USERS", true),
		DeleteMissingGroups: envBool("DELETE_MISSING_GROUPS", true),
		SkipServiceAccounts: envBool("SKIP_SERVICE_ACCOUNTS", true),
		PageSize:            envInt("PAGE_SIZE", defaultPageSize),
	}
	cfg.KeycloakClientSecret = strings.TrimSpace(os.Getenv("KEYCLOAK_CLIENT_SECRET"))
	cfg.KeycloakAuthRealm = strings.TrimSpace(os.Getenv("KEYCLOAK_AUTH_REALM"))
	if cfg.KeycloakAuthRealm == "" {
		if cfg.KeycloakClientSecret != "" {
			cfg.KeycloakAuthRealm = cfg.KeycloakRealm
		} else {
			cfg.KeycloakAuthRealm = "master"
		}
	}
	cfg.PDPSCIMBaseURL = strings.TrimRight(strings.TrimSpace(os.Getenv("PDP_SCIM_BASE_URL")), "/")
	if cfg.PDPSCIMBaseURL == "" && cfg.PDPOrganizationID != "" {
		cfg.PDPSCIMBaseURL = fmt.Sprintf("%s/scim/v2/%s", cfg.PDPBaseURL, url.PathEscape(cfg.PDPOrganizationID))
	}

	var missing []string
	if cfg.KeycloakBaseURL == "" {
		missing = append(missing, "KEYCLOAK_BASE_URL")
	}
	if cfg.KeycloakRealm == "" {
		missing = append(missing, "KEYCLOAK_REALM")
	}
	if cfg.KeycloakClientID == "" {
		missing = append(missing, "KEYCLOAK_CLIENT_ID")
	}
	if cfg.KeycloakClientSecret == "" && (cfg.KeycloakUsername == "" || cfg.KeycloakPassword == "") {
		missing = append(missing, "KEYCLOAK_CLIENT_SECRET or KEYCLOAK_ADMIN_USERNAME/KEYCLOAK_ADMIN_PASSWORD")
	}
	if cfg.PDPSCIMBaseURL == "" {
		missing = append(missing, "PDP_ORGANIZATION_ID or PDP_SCIM_BASE_URL")
	}
	if cfg.PDPSCIMToken == "" {
		missing = append(missing, "PDP_SCIM_TOKEN")
	}
	if cfg.SyncInterval <= 0 && !cfg.SyncOnce {
		missing = append(missing, "SYNC_INTERVAL>0 or SYNC_ONCE=true")
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = defaultPageSize
	}
	if len(missing) > 0 {
		return config{}, fmt.Errorf("missing %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

func syncDirectory(ctx context.Context, cfg config, kc *keycloakClient, scim *scimClient) (syncStats, error) {
	token, err := kc.accessToken(ctx)
	if err != nil {
		return syncStats{}, err
	}

	users, err := kc.users(ctx, token)
	if err != nil {
		return syncStats{}, err
	}
	groups, err := kc.groups(ctx, token)
	if err != nil {
		return syncStats{}, err
	}

	existingUsers, err := scim.users(ctx)
	if err != nil {
		return syncStats{}, err
	}
	existingGroups, err := scim.groups(ctx)
	if err != nil {
		return syncStats{}, err
	}

	stats := syncStats{}
	seenUsers := map[string]bool{}
	seenGroups := map[string]bool{}
	scimUserIDs := map[string]string{}

	for _, user := range users {
		if shouldSkipUser(user, cfg.SkipServiceAccounts) {
			continue
		}
		scimUser, err := scim.upsertUser(ctx, userToSCIM(user))
		if err != nil {
			return stats, fmt.Errorf("upsert user %s: %w", firstNonEmpty(user.Username, user.ID), err)
		}
		stats.UsersUpserted++
		seenUsers[user.ID] = true
		scimUserIDs[user.ID] = scimUser.ID
	}

	flatGroups := flattenGroups(groups)
	for _, group := range flatGroups {
		if strings.TrimSpace(group.ID) == "" {
			continue
		}
		members, err := kc.groupMembers(ctx, token, group.ID)
		if err != nil {
			return stats, fmt.Errorf("fetch members for group %s: %w", firstNonEmpty(group.Name, group.ID), err)
		}
		scimGroup, err := scim.upsertGroup(ctx, groupToSCIM(group, members, scimUserIDs, cfg.SkipServiceAccounts))
		if err != nil {
			return stats, fmt.Errorf("upsert group %s: %w", firstNonEmpty(group.Name, group.ID), err)
		}
		_ = scimGroup
		stats.GroupsUpserted++
		seenGroups[group.ID] = true
	}

	if cfg.DisableMissingUsers {
		for _, user := range existingUsers {
			if user.ExternalID == "" || seenUsers[user.ExternalID] {
				continue
			}
			if err := scim.deleteUser(ctx, user.ID); err != nil {
				return stats, fmt.Errorf("disable missing user %s: %w", firstNonEmpty(user.UserName, user.ExternalID, user.ID), err)
			}
			stats.UsersDeprovisioned++
		}
	}
	if cfg.DeleteMissingGroups {
		for _, group := range existingGroups {
			if group.ExternalID == "" || seenGroups[group.ExternalID] {
				continue
			}
			if err := scim.deleteGroup(ctx, group.ID); err != nil {
				return stats, fmt.Errorf("delete missing group %s: %w", firstNonEmpty(group.DisplayName, group.ExternalID, group.ID), err)
			}
			stats.GroupsDeprovisioned++
		}
	}
	return stats, nil
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

func (sc *scimClient) users(ctx context.Context) ([]scimUser, error) {
	var list scimListResponse[scimUser]
	if err := sc.doJSON(ctx, http.MethodGet, "/Users", nil, &list); err != nil {
		return nil, fmt.Errorf("list SCIM users: %w", err)
	}
	return list.Resources, nil
}

func (sc *scimClient) groups(ctx context.Context) ([]scimGroup, error) {
	var list scimListResponse[scimGroup]
	if err := sc.doJSON(ctx, http.MethodGet, "/Groups", nil, &list); err != nil {
		return nil, fmt.Errorf("list SCIM groups: %w", err)
	}
	return list.Resources, nil
}

func (sc *scimClient) upsertUser(ctx context.Context, user scimUser) (scimUser, error) {
	var out scimUser
	if err := sc.doJSON(ctx, http.MethodPost, "/Users", user, &out); err != nil {
		return scimUser{}, err
	}
	return out, nil
}

func (sc *scimClient) upsertGroup(ctx context.Context, group scimGroup) (scimGroup, error) {
	var out scimGroup
	if err := sc.doJSON(ctx, http.MethodPost, "/Groups", group, &out); err != nil {
		return scimGroup{}, err
	}
	return out, nil
}

func (sc *scimClient) deleteUser(ctx context.Context, id string) error {
	return sc.doJSON(ctx, http.MethodDelete, "/Users/"+url.PathEscape(id), nil, nil)
}

func (sc *scimClient) deleteGroup(ctx context.Context, id string) error {
	return sc.doJSON(ctx, http.MethodDelete, "/Groups/"+url.PathEscape(id), nil, nil)
}

func (sc *scimClient) doJSON(ctx context.Context, method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		payload, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, sc.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+sc.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req.Header.Set("Accept", "application/scim+json")
	resp, err := sc.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResponse(resp, out)
}

func decodeResponse(resp *http.Response, out any) error {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode response: %w: %s", err, strings.TrimSpace(string(raw)))
	}
	return nil
}

func userToSCIM(user keycloakUser) scimUser {
	active := true
	if user.Enabled != nil {
		active = *user.Enabled
	}
	display := strings.TrimSpace(strings.Join([]string{user.FirstName, user.LastName}, " "))
	if display == "" {
		display = firstNonEmpty(user.Username, user.Email, user.ID)
	}
	email := strings.TrimSpace(user.Email)
	if email == "" && strings.Contains(user.Username, "@") {
		email = user.Username
	}
	scim := scimUser{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ExternalID:  user.ID,
		UserName:    firstNonEmpty(user.Username, email, user.ID),
		DisplayName: display,
		Active:      &active,
	}
	if email != "" {
		scim.Emails = []scimEmail{{Value: email, Type: "work", Primary: true}}
	}
	return scim
}

func groupToSCIM(group keycloakGroup, members []keycloakUser, scimUserIDs map[string]string, skipServiceAccounts bool) scimGroup {
	scimMembers := make([]scimMember, 0, len(members))
	for _, member := range members {
		if shouldSkipUser(member, skipServiceAccounts) {
			continue
		}
		scimID := scimUserIDs[member.ID]
		if scimID == "" {
			continue
		}
		scimMembers = append(scimMembers, scimMember{
			Value:   scimID,
			Display: firstNonEmpty(member.Username, member.Email, member.ID),
		})
	}
	return scimGroup{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		ExternalID:  group.ID,
		DisplayName: firstNonEmpty(group.Name, strings.TrimPrefix(group.Path, "/"), group.ID),
		Members:     scimMembers,
	}
}

func flattenGroups(groups []keycloakGroup) []keycloakGroup {
	var flat []keycloakGroup
	var visit func([]keycloakGroup)
	visit = func(items []keycloakGroup) {
		for _, group := range items {
			flat = append(flat, group)
			if len(group.SubGroups) > 0 {
				visit(group.SubGroups)
			}
		}
	}
	visit(groups)
	return flat
}

func shouldSkipUser(user keycloakUser, skipServiceAccounts bool) bool {
	if strings.TrimSpace(user.ID) == "" {
		return true
	}
	return skipServiceAccounts && strings.HasPrefix(strings.ToLower(strings.TrimSpace(user.Username)), "service-account-")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func env(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		return time.Duration(seconds) * time.Second
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
