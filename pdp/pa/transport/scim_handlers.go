package transport

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
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

// handleSCIM handles inbound SCIM provisioning.
func (s *Server) handleSCIM(w http.ResponseWriter, r *http.Request) {
	segments := splitSCIMPath(r.URL.Path)
	if len(segments) < 2 {
		writeSCIMError(w, http.StatusNotFound, "SCIM organization and resource are required", "")
		return
	}

	organizationID := segments[0]
	resource := strings.ToLower(segments[1])
	resourceID := ""
	if len(segments) > 2 {
		resourceID = segments[2]
	}

	organization, idpCfg, ok := s.authenticateSCIMRequest(w, r, organizationID)
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
				"description": "Organization IdP SCIM bearer token",
			}},
		})
	case "users":
		s.handleSCIMUsers(w, r, organization, idpCfg, resourceID)
	case "groups":
		s.handleSCIMGroups(w, r, organization, idpCfg, resourceID)
	default:
		writeSCIMError(w, http.StatusNotFound, "unsupported SCIM resource", "")
	}
}
