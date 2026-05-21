package pa

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"licenta/features/catalog"

	"google.golang.org/protobuf/types/known/structpb"
)

func (client *Client) GetCatalog(ctx context.Context, accessToken, currentVersion string) (catalog.Catalog, error) {
	if client == nil {
		return catalog.Catalog{}, errors.New("PA client is nil")
	}
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return catalog.Catalog{}, errors.New("access token is required")
	}
	request, err := structpb.NewStruct(map[string]interface{}{"current_version": strings.TrimSpace(currentVersion)})
	if err != nil {
		return catalog.Catalog{}, fmt.Errorf("build catalog request: %w", err)
	}
	var response structpb.Struct
	if err := client.invoke(ctx, deviceCatalogGetCatalogPath, request, &response, invokeOptions{AccessToken: accessToken, UseMachineCertificate: true}); err != nil {
		return catalog.Catalog{}, err
	}
	return catalogFromStruct(&response, currentVersion)
}
func catalogFromStruct(value *structpb.Struct, currentVersion string) (catalog.Catalog, error) {
	version := strings.TrimSpace(structFieldString(value, "version"))
	if version == "" && structFieldBool(value, "not_modified") {
		version = strings.TrimSpace(currentVersion)
	}
	catalogSnapshot := catalog.Catalog{
		Version:       version,
		DNSSuffixes:   catalog.NormalizeSuffixes(structFieldStringList(value, "dns_suffixes")),
		Resources:     catalog.NormalizeResources(structFieldResourceList(value, "resources", "entries")),
		NotModified:   structFieldBool(value, "not_modified"),
		PolicyEpoch:   strings.TrimSpace(structFieldString(value, "policy_epoch")),
		PosturePolicy: catalog.NormalizePosturePolicy(posturePolicyFromStruct(structFieldStruct(value, "posture_policy"))),
	}
	if ttl, ok := structFieldNumber(value, "ttl_seconds"); ok {
		catalogSnapshot.TTLSeconds = int(ttl)
	}
	if catalogSnapshot.Version == "" {
		return catalog.Catalog{}, errors.New("catalog version is required")
	}
	return catalogSnapshot, nil
}

func posturePolicyFromStruct(value *structpb.Struct) catalog.PosturePolicy {
	if value == nil {
		return catalog.PosturePolicy{}
	}
	return catalog.PosturePolicy{
		RequiredChecks:      structFieldStringList(value, "required_checks"),
		RequiredCheckStatus: strings.TrimSpace(structFieldString(value, "required_check_status")),
	}
}
