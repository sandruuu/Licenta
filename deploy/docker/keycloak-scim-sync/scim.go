package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

type scimClient struct {
	baseURL string
	token   string
	http    *http.Client
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

func (sc *scimClient) users(ctx context.Context) ([]scimUser, error) {
	var list scimListResponse[scimUser]
	if err := sc.doJSON(ctx, http.MethodGet, "/Users", nil, &list); err != nil {
		return nil, err
	}
	return list.Resources, nil
}

func (sc *scimClient) groups(ctx context.Context) ([]scimGroup, error) {
	var list scimListResponse[scimGroup]
	if err := sc.doJSON(ctx, http.MethodGet, "/Groups", nil, &list); err != nil {
		return nil, err
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
