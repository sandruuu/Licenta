package transport

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pdp/models"
	"pdp/util"
)

const (
	scimUserSchema         = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema        = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema        = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatchOpSchema      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

type scimErrorResponse struct {
	Schemas  []string `json:"schemas"`
	Detail   string   `json:"detail"`
	Status   string   `json:"status"`
	SCIMType string   `json:"scimType,omitempty"`
}

type scimListResponse struct {
	Schemas      []string      `json:"schemas"`
	TotalResults int           `json:"totalResults"`
	Resources    []interface{} `json:"Resources"`
	StartIndex   int           `json:"startIndex"`
	ItemsPerPage int           `json:"itemsPerPage"`
}

type scimMeta struct {
	ResourceType string    `json:"resourceType,omitempty"`
	Created      time.Time `json:"created,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
	Location     string    `json:"location,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type scimName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}

type scimUserResource struct {
	Schemas     []string    `json:"schemas,omitempty"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName,omitempty"`
	Name        *scimName   `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Active      *bool       `json:"active,omitempty"`
	Emails      []scimEmail `json:"emails,omitempty"`
	Meta        *scimMeta   `json:"meta,omitempty"`
}

type scimMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

type scimGroupResource struct {
	Schemas     []string     `json:"schemas,omitempty"`
	ID          string       `json:"id,omitempty"`
	ExternalID  string       `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName,omitempty"`
	Members     []scimMember `json:"members,omitempty"`
	Meta        *scimMeta    `json:"meta,omitempty"`
}

type scimPatchRequest struct {
	Schemas    []string             `json:"schemas,omitempty"`
	Operations []scimPatchOperation `json:"Operations"`
}

type scimPatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

type scimFilter struct {
	Attribute string
	Value     string
}

// handleSCIM implements a deliberately small inbound SCIM surface for IdP
// provisioning: users, groups, and group memberships.
func (s *Server) handleSCIM(w http.ResponseWriter, r *http.Request) {
	segments := splitSCIMPath(r.URL.Path)
	if len(segments) < 2 {
		writeSCIMError(w, http.StatusNotFound, "SCIM tenant and resource are required", "")
		return
	}

	tenantID := segments[0]
	resource := strings.ToLower(segments[1])
	resourceID := ""
	if len(segments) > 2 {
		resourceID = segments[2]
	}

	tenant, idpCfg, ok := s.authenticateSCIMRequest(w, r, tenantID)
	if !ok {
		return
	}

	switch resource {
	case "serviceproviderconfig":
		if r.Method != http.MethodGet {
			writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed", "")
			return
		}
		writeSCIMJSON(w, http.StatusOK, map[string]interface{}{
			"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
			"patch":          map[string]bool{"supported": true},
			"bulk":           map[string]bool{"supported": false},
			"filter":         map[string]interface{}{"supported": true, "maxResults": 200},
			"changePassword": map[string]bool{"supported": false},
			"sort":           map[string]bool{"supported": false},
			"etag":           map[string]bool{"supported": false},
			"authenticationSchemes": []map[string]string{{
				"type":        "oauthbearertoken",
				"name":        "Bearer Token",
				"description": "Tenant IdP SCIM bearer token",
			}},
		})
	case "users":
		s.handleSCIMUsers(w, r, tenant, idpCfg, resourceID)
	case "groups":
		s.handleSCIMGroups(w, r, tenant, idpCfg, resourceID)
	default:
		writeSCIMError(w, http.StatusNotFound, "unsupported SCIM resource", "")
	}
}

func (s *Server) handleSCIMUsers(w http.ResponseWriter, r *http.Request, tenant *models.Tenant, idpCfg *models.IdentityProviderConfig, userID string) {
	switch r.Method {
	case http.MethodGet:
		if userID != "" {
			user, found := s.pa.Store.GetDirectoryUser(tenant.ID, idpCfg.ID, userID)
			if !found {
				writeSCIMError(w, http.StatusNotFound, "user not found", "")
				return
			}
			writeSCIMJSON(w, http.StatusOK, s.scimUserResponse(r, user))
			return
		}
		users := s.filteredDirectoryUsers(r, tenant.ID, idpCfg.ID)
		writeSCIMList(w, r, users, func(item interface{}) interface{} {
			return s.scimUserResponse(r, item.(*models.DirectoryUser))
		})
	case http.MethodPost:
		if userID != "" {
			writeSCIMError(w, http.StatusBadRequest, "POST must target /Users", "invalidPath")
			return
		}
		payload, raw, ok := decodeSCIMBody[scimUserResource](w, r)
		if !ok {
			return
		}
		user, status, ok := s.upsertSCIMUser(w, r, tenant.ID, idpCfg.ID, payload, raw, "")
		if !ok {
			return
		}
		writeSCIMJSON(w, status, s.scimUserResponse(r, user))
	case http.MethodPut:
		if userID == "" {
			writeSCIMError(w, http.StatusBadRequest, "user ID is required", "invalidPath")
			return
		}
		if _, found := s.pa.Store.GetDirectoryUser(tenant.ID, idpCfg.ID, userID); !found {
			writeSCIMError(w, http.StatusNotFound, "user not found", "")
			return
		}
		payload, raw, ok := decodeSCIMBody[scimUserResource](w, r)
		if !ok {
			return
		}
		user, _, ok := s.upsertSCIMUser(w, r, tenant.ID, idpCfg.ID, payload, raw, userID)
		if !ok {
			return
		}
		writeSCIMJSON(w, http.StatusOK, s.scimUserResponse(r, user))
	case http.MethodPatch:
		s.patchSCIMUser(w, r, tenant.ID, idpCfg.ID, userID)
	case http.MethodDelete:
		if userID == "" {
			writeSCIMError(w, http.StatusBadRequest, "user ID is required", "invalidPath")
			return
		}
		user, found := s.pa.Store.GetDirectoryUser(tenant.ID, idpCfg.ID, userID)
		if !found {
			writeSCIMError(w, http.StatusNotFound, "user not found", "")
			return
		}
		user.Active = false
		user.UpdatedAt = time.Now().UTC()
		s.pa.Store.SaveDirectoryUser(user)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed", "")
	}
}

func (s *Server) handleSCIMGroups(w http.ResponseWriter, r *http.Request, tenant *models.Tenant, idpCfg *models.IdentityProviderConfig, groupID string) {
	switch r.Method {
	case http.MethodGet:
		if groupID != "" {
			group, found := s.pa.Store.GetDirectoryGroup(tenant.ID, idpCfg.ID, groupID)
			if !found {
				writeSCIMError(w, http.StatusNotFound, "group not found", "")
				return
			}
			writeSCIMJSON(w, http.StatusOK, s.scimGroupResponse(r, group))
			return
		}
		groups := s.filteredDirectoryGroups(r, tenant.ID, idpCfg.ID)
		writeSCIMList(w, r, groups, func(item interface{}) interface{} {
			return s.scimGroupResponse(r, item.(*models.DirectoryGroup))
		})
	case http.MethodPost:
		if groupID != "" {
			writeSCIMError(w, http.StatusBadRequest, "POST must target /Groups", "invalidPath")
			return
		}
		payload, raw, ok := decodeSCIMBody[scimGroupResource](w, r)
		if !ok {
			return
		}
		group, status, ok := s.upsertSCIMGroup(w, r, tenant.ID, idpCfg.ID, payload, raw, "")
		if !ok {
			return
		}
		writeSCIMJSON(w, status, s.scimGroupResponse(r, group))
	case http.MethodPut:
		if groupID == "" {
			writeSCIMError(w, http.StatusBadRequest, "group ID is required", "invalidPath")
			return
		}
		if _, found := s.pa.Store.GetDirectoryGroup(tenant.ID, idpCfg.ID, groupID); !found {
			writeSCIMError(w, http.StatusNotFound, "group not found", "")
			return
		}
		payload, raw, ok := decodeSCIMBody[scimGroupResource](w, r)
		if !ok {
			return
		}
		group, _, ok := s.upsertSCIMGroup(w, r, tenant.ID, idpCfg.ID, payload, raw, groupID)
		if !ok {
			return
		}
		writeSCIMJSON(w, http.StatusOK, s.scimGroupResponse(r, group))
	case http.MethodPatch:
		s.patchSCIMGroup(w, r, tenant.ID, idpCfg.ID, groupID)
	case http.MethodDelete:
		if groupID == "" {
			writeSCIMError(w, http.StatusBadRequest, "group ID is required", "invalidPath")
			return
		}
		if !s.pa.Store.DeleteDirectoryGroup(tenant.ID, idpCfg.ID, groupID) {
			writeSCIMError(w, http.StatusNotFound, "group not found", "")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed", "")
	}
}

func (s *Server) upsertSCIMUser(w http.ResponseWriter, r *http.Request, tenantID, idpID string, payload scimUserResource, raw []byte, forcedID string) (*models.DirectoryUser, int, bool) {
	payload.UserName = strings.TrimSpace(payload.UserName)
	payload.ExternalID = strings.TrimSpace(payload.ExternalID)
	if payload.UserName == "" {
		payload.UserName = firstSCIMEmail(payload.Emails)
	}
	if payload.UserName == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName is required", "invalidValue")
		return nil, 0, false
	}

	var existing *models.DirectoryUser
	var found bool
	if forcedID != "" {
		existing, found = s.pa.Store.GetDirectoryUser(tenantID, idpID, forcedID)
	} else if payload.ExternalID != "" {
		existing, found = s.pa.Store.FindDirectoryUserByExternalID(tenantID, idpID, payload.ExternalID)
	}
	if !found {
		existing, found = s.pa.Store.FindDirectoryUserByUserName(tenantID, idpID, payload.UserName)
	}

	now := time.Now().UTC()
	status := http.StatusOK
	userID := forcedID
	createdAt := now
	if existing != nil {
		userID = existing.ID
		createdAt = existing.CreatedAt
	} else {
		if userID == "" {
			generated, err := util.GenerateID("dirusr")
			if err != nil {
				writeSCIMError(w, http.StatusInternalServerError, "failed to generate user ID", "")
				return nil, 0, false
			}
			userID = generated
		}
		status = http.StatusCreated
	}
	active := true
	if payload.Active != nil {
		active = *payload.Active
	} else if existing != nil {
		active = existing.Active
	}
	attributes := map[string]string{}
	if payload.Name != nil {
		if payload.Name.GivenName != "" {
			attributes["given_name"] = payload.Name.GivenName
		}
		if payload.Name.FamilyName != "" {
			attributes["family_name"] = payload.Name.FamilyName
		}
	}
	user := &models.DirectoryUser{
		ID:          userID,
		TenantID:    tenantID,
		IdPID:       idpID,
		ExternalID:  payload.ExternalID,
		UserName:    payload.UserName,
		DisplayName: strings.TrimSpace(payload.DisplayName),
		Email:       firstSCIMEmail(payload.Emails),
		Active:      active,
		Attributes:  attributes,
		RawJSON:     string(raw),
		CreatedAt:   createdAt,
		UpdatedAt:   now,
	}
	if user.DisplayName == "" {
		user.DisplayName = user.UserName
	}
	s.pa.Store.SaveDirectoryUser(user)
	return user, status, true
}

func (s *Server) upsertSCIMGroup(w http.ResponseWriter, r *http.Request, tenantID, idpID string, payload scimGroupResource, raw []byte, forcedID string) (*models.DirectoryGroup, int, bool) {
	payload.DisplayName = strings.TrimSpace(payload.DisplayName)
	payload.ExternalID = strings.TrimSpace(payload.ExternalID)
	if payload.DisplayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "displayName is required", "invalidValue")
		return nil, 0, false
	}

	var existing *models.DirectoryGroup
	var found bool
	if forcedID != "" {
		existing, found = s.pa.Store.GetDirectoryGroup(tenantID, idpID, forcedID)
	} else if payload.ExternalID != "" {
		existing, found = s.pa.Store.FindDirectoryGroupByExternalID(tenantID, idpID, payload.ExternalID)
	}
	if !found {
		existing, found = s.pa.Store.FindDirectoryGroupByDisplayName(tenantID, idpID, payload.DisplayName)
	}

	now := time.Now().UTC()
	status := http.StatusOK
	groupID := forcedID
	createdAt := now
	if existing != nil {
		groupID = existing.ID
		createdAt = existing.CreatedAt
	} else {
		if groupID == "" {
			generated, err := util.GenerateID("dirgrp")
			if err != nil {
				writeSCIMError(w, http.StatusInternalServerError, "failed to generate group ID", "")
				return nil, 0, false
			}
			groupID = generated
		}
		status = http.StatusCreated
	}

	group := &models.DirectoryGroup{
		ID:          groupID,
		TenantID:    tenantID,
		IdPID:       idpID,
		ExternalID:  payload.ExternalID,
		DisplayName: payload.DisplayName,
		RawJSON:     string(raw),
		CreatedAt:   createdAt,
		UpdatedAt:   now,
	}
	s.pa.Store.SaveDirectoryGroup(group)
	if err := s.pa.Store.ReplaceDirectoryGroupMembers(tenantID, idpID, group.ID, memberIDs(payload.Members), now); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "failed to save group members", "")
		return nil, 0, false
	}
	return group, status, true
}

func (s *Server) patchSCIMUser(w http.ResponseWriter, r *http.Request, tenantID, idpID, userID string) {
	if userID == "" {
		writeSCIMError(w, http.StatusBadRequest, "user ID is required", "invalidPath")
		return
	}
	user, found := s.pa.Store.GetDirectoryUser(tenantID, idpID, userID)
	if !found {
		writeSCIMError(w, http.StatusNotFound, "user not found", "")
		return
	}
	patch, _, ok := decodeSCIMBody[scimPatchRequest](w, r)
	if !ok {
		return
	}
	for _, op := range patch.Operations {
		if !applySCIMUserPatch(user, op) {
			writeSCIMError(w, http.StatusBadRequest, "unsupported user patch operation", "invalidPath")
			return
		}
	}
	user.UpdatedAt = time.Now().UTC()
	s.pa.Store.SaveDirectoryUser(user)
	writeSCIMJSON(w, http.StatusOK, s.scimUserResponse(r, user))
}

func (s *Server) patchSCIMGroup(w http.ResponseWriter, r *http.Request, tenantID, idpID, groupID string) {
	if groupID == "" {
		writeSCIMError(w, http.StatusBadRequest, "group ID is required", "invalidPath")
		return
	}
	group, found := s.pa.Store.GetDirectoryGroup(tenantID, idpID, groupID)
	if !found {
		writeSCIMError(w, http.StatusNotFound, "group not found", "")
		return
	}
	patch, _, ok := decodeSCIMBody[scimPatchRequest](w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	for _, op := range patch.Operations {
		if err := s.applySCIMGroupPatch(tenantID, idpID, group, op, now); err != nil {
			writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidPath")
			return
		}
	}
	group.UpdatedAt = now
	s.pa.Store.SaveDirectoryGroup(group)
	writeSCIMJSON(w, http.StatusOK, s.scimGroupResponse(r, group))
}

func applySCIMUserPatch(user *models.DirectoryUser, op scimPatchOperation) bool {
	if user == nil {
		return false
	}
	operation := strings.ToLower(strings.TrimSpace(op.Op))
	if operation == "" {
		operation = "replace"
	}
	path := strings.ToLower(strings.TrimSpace(op.Path))
	if path == "" {
		var partial scimUserResource
		if err := json.Unmarshal(op.Value, &partial); err != nil {
			return false
		}
		if partial.Active != nil {
			user.Active = *partial.Active
		}
		if strings.TrimSpace(partial.UserName) != "" {
			user.UserName = strings.TrimSpace(partial.UserName)
		}
		if strings.TrimSpace(partial.DisplayName) != "" {
			user.DisplayName = strings.TrimSpace(partial.DisplayName)
		}
		if email := firstSCIMEmail(partial.Emails); email != "" {
			user.Email = email
		}
		return true
	}
	switch operation {
	case "add", "replace":
		switch path {
		case "active":
			var active bool
			if err := json.Unmarshal(op.Value, &active); err != nil {
				return false
			}
			user.Active = active
		case "username":
			var userName string
			if err := json.Unmarshal(op.Value, &userName); err != nil {
				return false
			}
			user.UserName = strings.TrimSpace(userName)
		case "displayname":
			var displayName string
			if err := json.Unmarshal(op.Value, &displayName); err != nil {
				return false
			}
			user.DisplayName = strings.TrimSpace(displayName)
		case "emails":
			emails, ok := decodeSCIMEmails(op.Value)
			if !ok {
				return false
			}
			if email := firstSCIMEmail(emails); email != "" {
				user.Email = email
			}
		default:
			return false
		}
	case "remove":
		switch path {
		case "active":
			user.Active = false
		case "displayname":
			user.DisplayName = ""
		default:
			return false
		}
	default:
		return false
	}
	return true
}

func (s *Server) applySCIMGroupPatch(tenantID, idpID string, group *models.DirectoryGroup, op scimPatchOperation, now time.Time) error {
	operation := strings.ToLower(strings.TrimSpace(op.Op))
	if operation == "" {
		operation = "replace"
	}
	path := strings.ToLower(strings.TrimSpace(op.Path))
	if path == "" {
		var partial scimGroupResource
		if err := json.Unmarshal(op.Value, &partial); err != nil {
			return fmt.Errorf("invalid group patch value")
		}
		if strings.TrimSpace(partial.DisplayName) != "" {
			group.DisplayName = strings.TrimSpace(partial.DisplayName)
		}
		if partial.Members != nil {
			return s.pa.Store.ReplaceDirectoryGroupMembers(tenantID, idpID, group.ID, memberIDs(partial.Members), now)
		}
		return nil
	}
	if path == "displayname" {
		if operation != "add" && operation != "replace" {
			return fmt.Errorf("displayName only supports add/replace")
		}
		var displayName string
		if err := json.Unmarshal(op.Value, &displayName); err != nil {
			return fmt.Errorf("invalid displayName value")
		}
		group.DisplayName = strings.TrimSpace(displayName)
		return nil
	}
	if strings.HasPrefix(path, "members") {
		ids := memberIDsFromPatch(op.Value)
		if len(ids) == 0 {
			if filtered := memberIDFromFilterPath(path); filtered != "" {
				ids = []string{filtered}
			}
		}
		switch operation {
		case "add":
			return s.pa.Store.AddDirectoryGroupMembers(tenantID, idpID, group.ID, ids, now)
		case "replace":
			return s.pa.Store.ReplaceDirectoryGroupMembers(tenantID, idpID, group.ID, ids, now)
		case "remove":
			if len(ids) == 0 && path == "members" {
				return s.pa.Store.ReplaceDirectoryGroupMembers(tenantID, idpID, group.ID, nil, now)
			}
			return s.pa.Store.RemoveDirectoryGroupMembers(tenantID, idpID, group.ID, ids)
		default:
			return fmt.Errorf("unsupported members patch operation")
		}
	}
	return fmt.Errorf("unsupported group patch path")
}

func (s *Server) filteredDirectoryUsers(r *http.Request, tenantID, idpID string) []interface{} {
	users := s.pa.Store.ListDirectoryUsers(tenantID, idpID)
	filter, hasFilter := parseSCIMFilter(r.URL.Query().Get("filter"))
	result := make([]interface{}, 0, len(users))
	for _, user := range users {
		if user == nil {
			continue
		}
		if hasFilter && !matchesSCIMUserFilter(user, filter) {
			continue
		}
		result = append(result, user)
	}
	return result
}

func (s *Server) filteredDirectoryGroups(r *http.Request, tenantID, idpID string) []interface{} {
	groups := s.pa.Store.ListDirectoryGroups(tenantID, idpID)
	filter, hasFilter := parseSCIMFilter(r.URL.Query().Get("filter"))
	result := make([]interface{}, 0, len(groups))
	for _, group := range groups {
		if group == nil {
			continue
		}
		if hasFilter && !matchesSCIMGroupFilter(group, filter) {
			continue
		}
		result = append(result, group)
	}
	return result
}

func (s *Server) scimUserResponse(r *http.Request, user *models.DirectoryUser) scimUserResource {
	active := false
	if user != nil {
		active = user.Active
	}
	resp := scimUserResource{
		Schemas:     []string{scimUserSchema},
		ID:          user.ID,
		ExternalID:  user.ExternalID,
		UserName:    user.UserName,
		DisplayName: user.DisplayName,
		Active:      &active,
		Meta: &scimMeta{
			ResourceType: "User",
			Created:      user.CreatedAt,
			LastModified: user.UpdatedAt,
			Location:     scimLocation(r, "Users", user.ID),
		},
	}
	if user.Email != "" {
		resp.Emails = []scimEmail{{Value: user.Email, Type: "work", Primary: true}}
	}
	if user.Attributes != nil && (user.Attributes["given_name"] != "" || user.Attributes["family_name"] != "") {
		resp.Name = &scimName{
			GivenName:  user.Attributes["given_name"],
			FamilyName: user.Attributes["family_name"],
		}
	}
	return resp
}

func (s *Server) scimGroupResponse(r *http.Request, group *models.DirectoryGroup) scimGroupResource {
	members := s.pa.Store.ListDirectoryGroupMembers(group.TenantID, group.IdPID, group.ID)
	scimMembers := make([]scimMember, 0, len(members))
	for _, member := range members {
		if member == nil || strings.TrimSpace(member.UserID) == "" {
			continue
		}
		display := ""
		if user, ok := s.pa.Store.GetDirectoryUser(group.TenantID, group.IdPID, member.UserID); ok && user != nil {
			display = firstNonEmptySCIMString(user.DisplayName, user.UserName, user.Email)
		}
		scimMembers = append(scimMembers, scimMember{
			Value:   member.UserID,
			Display: display,
			Ref:     scimLocation(r, "Users", member.UserID),
		})
	}
	return scimGroupResource{
		Schemas:     []string{scimGroupSchema},
		ID:          group.ID,
		ExternalID:  group.ExternalID,
		DisplayName: group.DisplayName,
		Members:     scimMembers,
		Meta: &scimMeta{
			ResourceType: "Group",
			Created:      group.CreatedAt,
			LastModified: group.UpdatedAt,
			Location:     scimLocation(r, "Groups", group.ID),
		},
	}
}

func (s *Server) authenticateSCIMRequest(w http.ResponseWriter, r *http.Request, tenantID string) (*models.Tenant, *models.IdentityProviderConfig, bool) {
	if s == nil || s.pa == nil || s.pa.Store == nil {
		writeSCIMError(w, http.StatusServiceUnavailable, "SCIM store is unavailable", "")
		return nil, nil, false
	}
	tenant, found := s.pa.Store.GetTenant(tenantID)
	if !found || tenant == nil {
		writeSCIMError(w, http.StatusNotFound, "tenant not found", "")
		return nil, nil, false
	}
	if !tenant.Enabled {
		writeSCIMError(w, http.StatusForbidden, "tenant is disabled", "")
		return nil, nil, false
	}
	token, err := bearerToken(r)
	if err != nil {
		writeSCIMError(w, http.StatusUnauthorized, "SCIM bearer token is required", "")
		return nil, nil, false
	}
	for _, cfg := range s.pa.Store.ListIdentityProviderConfigsForTenant(tenant.ID) {
		if cfg == nil || !cfg.Enabled || strings.TrimSpace(cfg.SCIMToken) == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(cfg.SCIMToken)) == 1 {
			return tenant, cfg, true
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
