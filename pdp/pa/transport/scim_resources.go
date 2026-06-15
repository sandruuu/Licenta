package transport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"pdp/models"
	"pdp/util"
)

func (s *Server) handleSCIMUsers(w http.ResponseWriter, r *http.Request, organization *models.Organization, idpCfg *models.IdentityProviderConfig, userID string) {
	switch r.Method {
	case http.MethodGet:
		if userID != "" {
			user, found := s.pa.Store.GetDirectoryUser(organization.ID, idpCfg.ID, userID)
			if !found {
				writeSCIMError(w, http.StatusNotFound, "user not found", "")
				return
			}
			writeSCIMJSON(w, http.StatusOK, s.scimUserResponse(r, user))
			return
		}
		users := s.filteredDirectoryUsers(r, organization.ID, idpCfg.ID)
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
		user, status, ok := s.upsertSCIMUser(w, r, organization.ID, idpCfg.ID, payload, raw, "")
		if !ok {
			return
		}
		writeSCIMJSON(w, status, s.scimUserResponse(r, user))
	case http.MethodPut:
		if userID == "" {
			writeSCIMError(w, http.StatusBadRequest, "user ID is required", "invalidPath")
			return
		}
		if _, found := s.pa.Store.GetDirectoryUser(organization.ID, idpCfg.ID, userID); !found {
			writeSCIMError(w, http.StatusNotFound, "user not found", "")
			return
		}
		payload, raw, ok := decodeSCIMBody[scimUserResource](w, r)
		if !ok {
			return
		}
		user, _, ok := s.upsertSCIMUser(w, r, organization.ID, idpCfg.ID, payload, raw, userID)
		if !ok {
			return
		}
		writeSCIMJSON(w, http.StatusOK, s.scimUserResponse(r, user))
	case http.MethodPatch:
		s.patchSCIMUser(w, r, organization.ID, idpCfg.ID, userID)
	case http.MethodDelete:
		if userID == "" {
			writeSCIMError(w, http.StatusBadRequest, "user ID is required", "invalidPath")
			return
		}
		user, found := s.pa.Store.GetDirectoryUser(organization.ID, idpCfg.ID, userID)
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

func (s *Server) handleSCIMGroups(w http.ResponseWriter, r *http.Request, organization *models.Organization, idpCfg *models.IdentityProviderConfig, groupID string) {
	switch r.Method {
	case http.MethodGet:
		if groupID != "" {
			group, found := s.pa.Store.GetDirectoryGroup(organization.ID, idpCfg.ID, groupID)
			if !found {
				writeSCIMError(w, http.StatusNotFound, "group not found", "")
				return
			}
			writeSCIMJSON(w, http.StatusOK, s.scimGroupResponse(r, group))
			return
		}
		groups := s.filteredDirectoryGroups(r, organization.ID, idpCfg.ID)
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
		group, status, ok := s.upsertSCIMGroup(w, r, organization.ID, idpCfg.ID, payload, raw, "")
		if !ok {
			return
		}
		writeSCIMJSON(w, status, s.scimGroupResponse(r, group))
	case http.MethodPut:
		if groupID == "" {
			writeSCIMError(w, http.StatusBadRequest, "group ID is required", "invalidPath")
			return
		}
		if _, found := s.pa.Store.GetDirectoryGroup(organization.ID, idpCfg.ID, groupID); !found {
			writeSCIMError(w, http.StatusNotFound, "group not found", "")
			return
		}
		payload, raw, ok := decodeSCIMBody[scimGroupResource](w, r)
		if !ok {
			return
		}
		group, _, ok := s.upsertSCIMGroup(w, r, organization.ID, idpCfg.ID, payload, raw, groupID)
		if !ok {
			return
		}
		writeSCIMJSON(w, http.StatusOK, s.scimGroupResponse(r, group))
	case http.MethodPatch:
		s.patchSCIMGroup(w, r, organization.ID, idpCfg.ID, groupID)
	case http.MethodDelete:
		if groupID == "" {
			writeSCIMError(w, http.StatusBadRequest, "group ID is required", "invalidPath")
			return
		}
		if !s.pa.Store.DeleteDirectoryGroup(organization.ID, idpCfg.ID, groupID) {
			writeSCIMError(w, http.StatusNotFound, "group not found", "")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed", "")
	}
}

func (s *Server) upsertSCIMUser(w http.ResponseWriter, r *http.Request, organizationID, idpID string, payload scimUserResource, raw []byte, forcedID string) (*models.DirectoryUser, int, bool) {
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
		existing, found = s.pa.Store.GetDirectoryUser(organizationID, idpID, forcedID)
	} else if payload.ExternalID != "" {
		existing, found = s.pa.Store.FindDirectoryUserByExternalID(organizationID, idpID, payload.ExternalID)
	}
	if !found {
		existing, found = s.pa.Store.FindDirectoryUserByUserName(organizationID, idpID, payload.UserName)
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
		ID:             userID,
		OrganizationID: organizationID,
		IdPID:          idpID,
		ExternalID:     payload.ExternalID,
		UserName:       payload.UserName,
		DisplayName:    strings.TrimSpace(payload.DisplayName),
		Email:          firstSCIMEmail(payload.Emails),
		Active:         active,
		Attributes:     attributes,
		RawJSON:        string(raw),
		CreatedAt:      createdAt,
		UpdatedAt:      now,
	}
	if user.DisplayName == "" {
		user.DisplayName = user.UserName
	}
	s.pa.Store.SaveDirectoryUser(user)
	return user, status, true
}

func (s *Server) upsertSCIMGroup(w http.ResponseWriter, r *http.Request, organizationID, idpID string, payload scimGroupResource, raw []byte, forcedID string) (*models.DirectoryGroup, int, bool) {
	payload.DisplayName = strings.TrimSpace(payload.DisplayName)
	payload.ExternalID = strings.TrimSpace(payload.ExternalID)
	if payload.DisplayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "displayName is required", "invalidValue")
		return nil, 0, false
	}

	var existing *models.DirectoryGroup
	var found bool
	if forcedID != "" {
		existing, found = s.pa.Store.GetDirectoryGroup(organizationID, idpID, forcedID)
	} else if payload.ExternalID != "" {
		existing, found = s.pa.Store.FindDirectoryGroupByExternalID(organizationID, idpID, payload.ExternalID)
	}
	if !found {
		existing, found = s.pa.Store.FindDirectoryGroupByDisplayName(organizationID, idpID, payload.DisplayName)
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
		ID:             groupID,
		OrganizationID: organizationID,
		IdPID:          idpID,
		ExternalID:     payload.ExternalID,
		DisplayName:    payload.DisplayName,
		RawJSON:        string(raw),
		CreatedAt:      createdAt,
		UpdatedAt:      now,
	}
	s.pa.Store.SaveDirectoryGroup(group)
	if err := s.pa.Store.ReplaceDirectoryGroupMembers(organizationID, idpID, group.ID, memberIDs(payload.Members), now); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "failed to save group members", "")
		return nil, 0, false
	}
	return group, status, true
}

func (s *Server) patchSCIMUser(w http.ResponseWriter, r *http.Request, organizationID, idpID, userID string) {
	if userID == "" {
		writeSCIMError(w, http.StatusBadRequest, "user ID is required", "invalidPath")
		return
	}
	user, found := s.pa.Store.GetDirectoryUser(organizationID, idpID, userID)
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

func (s *Server) patchSCIMGroup(w http.ResponseWriter, r *http.Request, organizationID, idpID, groupID string) {
	if groupID == "" {
		writeSCIMError(w, http.StatusBadRequest, "group ID is required", "invalidPath")
		return
	}
	group, found := s.pa.Store.GetDirectoryGroup(organizationID, idpID, groupID)
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
		if err := s.applySCIMGroupPatch(organizationID, idpID, group, op, now); err != nil {
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

func (s *Server) applySCIMGroupPatch(organizationID, idpID string, group *models.DirectoryGroup, op scimPatchOperation, now time.Time) error {
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
			return s.pa.Store.ReplaceDirectoryGroupMembers(organizationID, idpID, group.ID, memberIDs(partial.Members), now)
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
			return s.pa.Store.AddDirectoryGroupMembers(organizationID, idpID, group.ID, ids, now)
		case "replace":
			return s.pa.Store.ReplaceDirectoryGroupMembers(organizationID, idpID, group.ID, ids, now)
		case "remove":
			if len(ids) == 0 && path == "members" {
				return s.pa.Store.ReplaceDirectoryGroupMembers(organizationID, idpID, group.ID, nil, now)
			}
			return s.pa.Store.RemoveDirectoryGroupMembers(organizationID, idpID, group.ID, ids)
		default:
			return fmt.Errorf("unsupported members patch operation")
		}
	}
	return fmt.Errorf("unsupported group patch path")
}

func (s *Server) filteredDirectoryUsers(r *http.Request, organizationID, idpID string) []interface{} {
	users := s.pa.Store.ListDirectoryUsers(organizationID, idpID)
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

func (s *Server) filteredDirectoryGroups(r *http.Request, organizationID, idpID string) []interface{} {
	groups := s.pa.Store.ListDirectoryGroups(organizationID, idpID)
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
	members := s.pa.Store.ListDirectoryGroupMembers(group.OrganizationID, group.IdPID, group.ID)
	scimMembers := make([]scimMember, 0, len(members))
	for _, member := range members {
		if member == nil || strings.TrimSpace(member.UserID) == "" {
			continue
		}
		display := ""
		if user, ok := s.pa.Store.GetDirectoryUser(group.OrganizationID, group.IdPID, member.UserID); ok && user != nil {
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
