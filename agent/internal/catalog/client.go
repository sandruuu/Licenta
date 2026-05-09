package catalog

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
)

const deviceCatalogGRPCGetCatalogPath = "/ztna.catalog.v1.DeviceCatalogService/GetCatalog"

type ClientCertificateProvider func(context.Context) (tls.Certificate, error)

type Config struct {
	CloudURL                  string
	CAFile                    string
	ClientCertificateProvider ClientCertificateProvider
	Timeout                   time.Duration
	DialOptions               []grpc.DialOption
}

type Client struct {
	cloudURL                  string
	caFile                    string
	clientCertificateProvider ClientCertificateProvider
	timeout                   time.Duration
	dialOptions               []grpc.DialOption
}

type Catalog struct {
	Version     string
	DNSSuffixes []string
	Resources   []Resource
	TTLSeconds  int
	NotModified bool
	PolicyEpoch string
}

type Resource struct {
	FQDN       string `json:"fqdn"`
	ResourceID string `json:"resource_id,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Port       int    `json:"port,omitempty"`
}

func NewClient(config Config) (*Client, error) {
	cloudURL := strings.TrimRight(strings.TrimSpace(config.CloudURL), "/")
	if cloudURL == "" {
		return nil, errors.New("cloud URL is required")
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		cloudURL:                  cloudURL,
		caFile:                    strings.TrimSpace(config.CAFile),
		clientCertificateProvider: config.ClientCertificateProvider,
		timeout:                   timeout,
		dialOptions:               append([]grpc.DialOption(nil), config.DialOptions...),
	}, nil
}

func (client *Client) GetCatalog(ctx context.Context, accessToken, currentVersion string) (Catalog, error) {
	if client == nil {
		return Catalog{}, errors.New("catalog client is nil")
	}
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return Catalog{}, errors.New("access token is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	request, err := structpb.NewStruct(map[string]interface{}{"current_version": strings.TrimSpace(currentVersion)})
	if err != nil {
		return Catalog{}, fmt.Errorf("build catalog gRPC request: %w", err)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+accessToken)
	var response structpb.Struct
	if err := client.invoke(ctx, deviceCatalogGRPCGetCatalogPath, request, &response); err != nil {
		return Catalog{}, err
	}
	return catalogFromStruct(&response, currentVersion)
}

func (client *Client) invoke(ctx context.Context, method string, request *structpb.Struct, response *structpb.Struct) error {
	if client.clientCertificateProvider == nil {
		return errors.New("client certificate provider is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, client.timeout)
		defer cancel()
	}
	clientCertificate, err := client.clientCertificateProvider(ctx)
	if err != nil {
		return fmt.Errorf("load catalog gRPC mTLS credential: %w", err)
	}
	target, serverName, err := grpcTargetFromCloudURL(client.cloudURL)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{clientCertificate},
	}
	if serverName != "" {
		tlsConfig.ServerName = serverName
	}
	if client.caFile != "" {
		pool, err := rootCAPool(client.caFile)
		if err != nil {
			return err
		}
		tlsConfig.RootCAs = pool
	}
	dialOptions := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}
	dialOptions = append(dialOptions, client.dialOptions...)
	conn, err := grpc.DialContext(ctx, target, dialOptions...)
	if err != nil {
		return fmt.Errorf("dial catalog gRPC endpoint: %w", err)
	}
	defer conn.Close()
	if err := conn.Invoke(ctx, method, request, response); err != nil {
		return fmt.Errorf("invoke catalog gRPC method %s: %w", method, err)
	}
	return nil
}

func catalogFromStruct(value *structpb.Struct, currentVersion string) (Catalog, error) {
	version := strings.TrimSpace(structFieldString(value, "version"))
	if version == "" && structFieldBool(value, "not_modified") {
		version = strings.TrimSpace(currentVersion)
	}
	catalog := Catalog{
		Version:     version,
		DNSSuffixes: NormalizeSuffixes(structFieldStringList(value, "dns_suffixes")),
		Resources:   NormalizeResources(structFieldResourceList(value, "resources", "entries")),
		NotModified: structFieldBool(value, "not_modified"),
		PolicyEpoch: strings.TrimSpace(structFieldString(value, "policy_epoch")),
	}
	if ttl, ok := structFieldNumber(value, "ttl_seconds"); ok {
		catalog.TTLSeconds = int(ttl)
	}
	if catalog.Version == "" {
		return Catalog{}, errors.New("catalog version is required")
	}
	return catalog, nil
}

func NormalizeResources(values []Resource) []Resource {
	seen := make(map[string]Resource, len(values))
	for _, value := range values {
		resource := Resource{
			FQDN:       normalizeHost(value.FQDN),
			ResourceID: strings.TrimSpace(value.ResourceID),
			Protocol:   strings.ToLower(strings.TrimSpace(value.Protocol)),
			Port:       value.Port,
		}
		if resource.FQDN == "" {
			continue
		}
		if resource.Protocol == "" {
			resource.Protocol = "tcp"
		}
		if resource.Port < 0 {
			resource.Port = 0
		}
		seen[resource.FQDN] = resource
	}
	resources := make([]Resource, 0, len(seen))
	for _, resource := range seen {
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(left, right int) bool {
		return resources[left].FQDN < resources[right].FQDN
	})
	return resources
}

func NormalizeSuffixes(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		suffix := normalizeSuffix(value)
		if suffix != "" {
			seen[suffix] = struct{}{}
		}
	}
	suffixes := make([]string, 0, len(seen))
	for suffix := range seen {
		suffixes = append(suffixes, suffix)
	}
	sort.Strings(suffixes)
	return suffixes
}

func normalizeSuffix(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimPrefix(value, ".")
	value = strings.TrimSuffix(value, ".")
	if value == "" || !strings.Contains(value, ".") || strings.ContainsAny(value, " /\\:\x00") || net.ParseIP(value) != nil {
		return ""
	}
	return value
}

func normalizeHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return ""
		}
		value = parsed.Hostname()
	} else if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(strings.TrimSpace(value), "[]")
	value = strings.TrimSuffix(value, ".")
	if value == "" || !strings.Contains(value, ".") || strings.ContainsAny(value, " /\\:\x00") || net.ParseIP(value) != nil {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || strings.Contains(label, "*") {
			return ""
		}
	}
	return value
}

func rootCAPool(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("CA file does not contain PEM certificates")
	}
	return pool, nil
}

func grpcTargetFromCloudURL(raw string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("parse cloud URL: %w", err)
	}
	host := parsed.Host
	if host == "" && parsed.Scheme == "" && parsed.Path != "" {
		host = parsed.Path
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", "", errors.New("cloud URL host is required")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}
	serverName := parsed.Hostname()
	if serverName == "" {
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			serverName = splitHost
		}
	}
	return host, serverName, nil
}

func structFieldString(value *structpb.Struct, key string) string {
	if value == nil {
		return ""
	}
	field, ok := value.GetFields()[key]
	if !ok || field == nil {
		return ""
	}
	return field.GetStringValue()
}

func structFieldBool(value *structpb.Struct, key string) bool {
	if value == nil {
		return false
	}
	field, ok := value.GetFields()[key]
	if !ok || field == nil {
		return false
	}
	return field.GetBoolValue()
}

func structFieldNumber(value *structpb.Struct, key string) (float64, bool) {
	if value == nil {
		return 0, false
	}
	field, ok := value.GetFields()[key]
	if !ok || field == nil {
		return 0, false
	}
	return field.GetNumberValue(), true
}

func structFieldStringList(value *structpb.Struct, key string) []string {
	if value == nil {
		return nil
	}
	field, ok := value.GetFields()[key]
	if !ok || field == nil || field.GetListValue() == nil {
		return nil
	}
	values := field.GetListValue().GetValues()
	stringsOut := make([]string, 0, len(values))
	for _, item := range values {
		if item == nil {
			continue
		}
		stringsOut = append(stringsOut, item.GetStringValue())
	}
	return stringsOut
}

func structFieldResourceList(value *structpb.Struct, keys ...string) []Resource {
	if value == nil {
		return nil
	}
	var resources []Resource
	for _, key := range keys {
		field, ok := value.GetFields()[key]
		if !ok || field == nil || field.GetListValue() == nil {
			continue
		}
		for _, item := range field.GetListValue().GetValues() {
			if item == nil || item.GetStructValue() == nil {
				continue
			}
			fields := item.GetStructValue().GetFields()
			resource := Resource{
				FQDN:       strings.TrimSpace(fields["fqdn"].GetStringValue()),
				ResourceID: strings.TrimSpace(fields["resource_id"].GetStringValue()),
				Protocol:   strings.TrimSpace(fields["protocol"].GetStringValue()),
			}
			if numberField := fields["port"]; numberField != nil {
				resource.Port = int(numberField.GetNumberValue())
			}
			resources = append(resources, resource)
		}
	}
	return NormalizeResources(resources)
}
