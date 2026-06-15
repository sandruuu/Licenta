package transport

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"pdp/models"
)

func (s *Server) authenticateSCIMRequest(w http.ResponseWriter, r *http.Request, organizationID string) (*models.Organization, *models.IdentityProviderConfig, bool) {
	if s == nil || s.pa == nil || s.pa.Store == nil {
		writeSCIMError(w, http.StatusServiceUnavailable, "SCIM store is unavailable", "")
		return nil, nil, false
	}
	organization, found := s.pa.Store.GetOrganization(organizationID)
	if !found || organization == nil {
		writeSCIMError(w, http.StatusNotFound, "organization not found", "")
		return nil, nil, false
	}
	if !organization.Enabled {
		writeSCIMError(w, http.StatusForbidden, "organization is disabled", "")
		return nil, nil, false
	}
	token, err := bearerToken(r)
	if err != nil {
		writeSCIMError(w, http.StatusUnauthorized, "SCIM bearer token is required", "")
		return nil, nil, false
	}
	for _, cfg := range s.pa.Store.ListIdentityProviderConfigsForOrganization(organization.ID) {
		if cfg == nil || !cfg.Enabled || strings.TrimSpace(cfg.SCIMToken) == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(cfg.SCIMToken)) == 1 {
			return organization, cfg, true
		}
	}
	writeSCIMError(w, http.StatusUnauthorized, "invalid SCIM bearer token", "")
	return nil, nil, false
}

func writeSCIMList(w http.ResponseWriter, r *http.Request, items []interface{}, convert func(interface{}) interface{}) {
	startIndex := intQuery(r, "startIndex", 1)
	if startIndex < 1 {
		startIndex = 1
	}
	count := intQuery(r, "count", len(items))
	if count < 0 {
		count = 0
	}
	start := startIndex - 1
	if start > len(items) {
		start = len(items)
	}
	end := len(items)
	if count >= 0 && start+count < end {
		end = start + count
	}
	resources := make([]interface{}, 0, end-start)
	for _, item := range items[start:end] {
		resources = append(resources, convert(item))
	}
	writeSCIMJSON(w, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListResponseSchema},
		TotalResults: len(items),
		Resources:    resources,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
	})
}

func writeSCIMJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeSCIMError(w http.ResponseWriter, status int, detail, scimType string) {
	writeSCIMJSON(w, status, scimErrorResponse{
		Schemas:  []string{scimErrorSchema},
		Detail:   detail,
		Status:   strconv.Itoa(status),
		SCIMType: scimType,
	})
}

func decodeSCIMBody[T any](w http.ResponseWriter, r *http.Request) (T, []byte, bool) {
	var payload T
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid request body", "")
		return payload, nil, false
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON body", "invalidSyntax")
		return payload, nil, false
	}
	return payload, body, true
}

func splitSCIMPath(path string) []string {
	path = strings.Trim(strings.TrimPrefix(path, "/scim/v2/"), "/")
	if path == "" {
		return nil
	}
	parts := strings.Split(path, "/")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func firstSCIMEmail(emails []scimEmail) string {
	for _, email := range emails {
		if email.Primary && strings.TrimSpace(email.Value) != "" {
			return strings.TrimSpace(email.Value)
		}
	}
	for _, email := range emails {
		if strings.TrimSpace(email.Value) != "" {
			return strings.TrimSpace(email.Value)
		}
	}
	return ""
}

func firstNonEmptySCIMString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func memberIDs(members []scimMember) []string {
	ids := make([]string, 0, len(members))
	for _, member := range members {
		if value := strings.TrimSpace(member.Value); value != "" {
			ids = append(ids, value)
		}
	}
	return ids
}

func memberIDsFromPatch(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var members []scimMember
	if err := json.Unmarshal(raw, &members); err == nil {
		return memberIDs(members)
	}
	var member scimMember
	if err := json.Unmarshal(raw, &member); err == nil && member.Value != "" {
		return []string{strings.TrimSpace(member.Value)}
	}
	var wrapper struct {
		Members []scimMember `json:"members"`
		Value   string       `json:"value"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil {
		ids := memberIDs(wrapper.Members)
		if wrapper.Value != "" {
			ids = append(ids, strings.TrimSpace(wrapper.Value))
		}
		return ids
	}
	var value string
	if err := json.Unmarshal(raw, &value); err == nil && strings.TrimSpace(value) != "" {
		return []string{strings.TrimSpace(value)}
	}
	return nil
}

func memberIDFromFilterPath(path string) string {
	needle := "value eq \""
	lower := strings.ToLower(path)
	idx := strings.Index(lower, needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	end := strings.Index(path[start:], "\"")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(path[start : start+end])
}

func decodeSCIMEmails(raw json.RawMessage) ([]scimEmail, bool) {
	var emails []scimEmail
	if err := json.Unmarshal(raw, &emails); err == nil {
		return emails, true
	}
	var email scimEmail
	if err := json.Unmarshal(raw, &email); err == nil && email.Value != "" {
		return []scimEmail{email}, true
	}
	return nil, false
}

func parseSCIMFilter(raw string) (scimFilter, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return scimFilter{}, false
	}
	parts := strings.SplitN(raw, " eq ", 2)
	if len(parts) != 2 {
		parts = strings.SplitN(raw, " EQ ", 2)
	}
	if len(parts) != 2 {
		return scimFilter{}, false
	}
	value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
	return scimFilter{Attribute: strings.ToLower(strings.TrimSpace(parts[0])), Value: value}, true
}

func matchesSCIMUserFilter(user *models.DirectoryUser, filter scimFilter) bool {
	switch filter.Attribute {
	case "id":
		return strings.EqualFold(user.ID, filter.Value)
	case "externalid":
		return strings.EqualFold(user.ExternalID, filter.Value)
	case "username":
		return strings.EqualFold(user.UserName, filter.Value)
	case "emails.value":
		return strings.EqualFold(user.Email, filter.Value)
	default:
		return true
	}
}

func matchesSCIMGroupFilter(group *models.DirectoryGroup, filter scimFilter) bool {
	switch filter.Attribute {
	case "id":
		return strings.EqualFold(group.ID, filter.Value)
	case "externalid":
		return strings.EqualFold(group.ExternalID, filter.Value)
	case "displayname":
		return strings.EqualFold(group.DisplayName, filter.Value)
	default:
		return true
	}
}

func scimLocation(r *http.Request, resourceType, id string) string {
	if r == nil || strings.TrimSpace(id) == "" {
		return ""
	}
	segments := splitSCIMPath(r.URL.Path)
	if len(segments) == 0 {
		return ""
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/scim/v2/%s/%s/%s", scheme, r.Host, segments[0], resourceType, id)
}

func intQuery(r *http.Request, key string, fallback int) int {
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
