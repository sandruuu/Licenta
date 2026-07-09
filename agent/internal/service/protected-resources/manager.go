package protectedresources

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"agent/internal/ipc"
	dnscontrol "agent/internal/service/dns-control"
	dnsresolver "agent/internal/service/dns-resolver"
	trafficinterception "agent/internal/service/traffic-interception"
)

const (
	defaultReadyTimeout = 2 * time.Second
)

type Config struct {
	DNSListenAddress string
	DNSServer        string
	SyntheticIPCIDR  string
	HardenDoH        bool
	ReadyTimeout     time.Duration

	TrafficInterceptionEnabled bool
	TrafficProxyListenAddress  string
	WFPDriverDevicePath        string
	WFPFailClosed              bool
}

type Dependencies struct {
	Logger             *slog.Logger
	DNSControl         DNSControl
	TrafficInterceptor TrafficInterceptor
	TrafficConnector   trafficinterception.StreamConnector
}

type DNSControl interface {
	Apply(context.Context, dnscontrol.Config) error
}

type TrafficInterceptor interface {
	Run(context.Context) error
	ApplyMappings(context.Context, []trafficinterception.ResourceMapping) error
	Clear(context.Context) error
	Status() trafficinterception.Status
}

type Manager struct {
	logger       *slog.Logger
	config       Config
	resolver     *dnsresolver.Resolver
	server       *dnsresolver.Server
	dnsControl   DNSControl
	traffic      TrafficInterceptor
	readyTimeout time.Duration

	mu      sync.RWMutex
	running bool
	status  Status
}

type Status struct {
	DNSListenAddress     string
	DNSServer            string
	SyntheticIPCIDR      string
	ResolverState        string
	NRPTRuleCount        int
	ResourceCount        int
	ActiveMappingCount   int
	CatalogVersion       string
	PolicyEpoch          string
	LastCatalogAppliedAt time.Time
	TrafficState         string
	TrafficProxyAddress  string
	TrafficRuleCount     int
	WFPRuleState         string
	LastError            string
}

func NewManager(config Config, dependencies Dependencies) (*Manager, error) {
	if dependencies.Logger == nil {
		dependencies.Logger = slog.Default()
	}
	config = normalizeConfig(config)
	resolver, err := dnsresolver.New(dnsresolver.Options{CGNATCIDR: config.SyntheticIPCIDR})
	if err != nil {
		return nil, err
	}
	server, err := dnsresolver.NewServer(dnsresolver.ServerOptions{
		ListenAddress: config.DNSListenAddress,
		Resolver:      resolver,
	})
	if err != nil {
		return nil, err
	}
	dnsControl := dependencies.DNSControl
	if dnsControl == nil {
		dnsControl = dnscontrol.NewManager()
	}
	traffic := dependencies.TrafficInterceptor
	if traffic == nil {
		trafficManager, err := trafficinterception.NewManager(trafficConfigFromConfig(config), trafficinterception.Dependencies{
			Logger:    dependencies.Logger,
			Connector: dependencies.TrafficConnector,
		})
		if err != nil {
			return nil, err
		}
		traffic = trafficManager
	}
	return &Manager{
		logger:       dependencies.Logger,
		config:       config,
		resolver:     resolver,
		server:       server,
		dnsControl:   dnsControl,
		traffic:      traffic,
		readyTimeout: firstPositiveDuration(config.ReadyTimeout, defaultReadyTimeout),
		status: Status{
			DNSListenAddress: config.DNSListenAddress,
			DNSServer:        config.DNSServer,
			SyntheticIPCIDR:  config.SyntheticIPCIDR,
			ResolverState:    dnsresolver.StatusWaiting,
			TrafficState:     trafficinterception.StatusDisabled,
		},
	}, nil
}

func (manager *Manager) Run(ctx context.Context) error {
	if manager == nil {
		return errors.New("protected resources manager is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := manager.Clear(ctx); err != nil {
		manager.logger.Warn("could not clear stale protected resource rules on startup", "error", err)
	}
	manager.setRunning(true)
	if manager.traffic != nil {
		go func() {
			if err := manager.traffic.Run(ctx); err != nil && !errors.Is(err, context.Canceled) && ctx.Err() == nil {
				manager.setError(fmt.Errorf("traffic interception stopped: %w", err))
			}
		}()
	}
	err := manager.server.Run(ctx)
	manager.setRunning(false)
	if err != nil && !errors.Is(err, context.Canceled) && ctx.Err() == nil {
		manager.setError(err)
		return err
	}
	return nil
}

func (manager *Manager) ApplyCatalog(ctx context.Context, catalog ipc.CatalogInfo) error {
	if manager == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	policy := resolverPolicyFromCatalog(catalog)
	nrptNames := nrptNamesFromCatalog(catalog)
	if len(nrptNames) > 0 || len(policy.Resources) > 0 {
		if err := manager.waitUntilDNSReady(ctx); err != nil {
			manager.setError(err)
			return err
		}
	}
	if err := manager.resolver.ApplyPolicy(policy); err != nil {
		manager.setError(err)
		return err
	}
	if manager.config.TrafficInterceptionEnabled {
		mappings, err := manager.resolver.EnsureMappings()
		if err != nil {
			_ = manager.resolver.ApplyPolicy(dnsresolver.Policy{})
			manager.setError(err)
			return err
		}
		if err := manager.traffic.ApplyMappings(ctx, trafficMappingsFromDNS(mappings)); err != nil {
			_ = manager.resolver.ApplyPolicy(dnsresolver.Policy{})
			_ = manager.traffic.Clear(ctx)
			manager.setError(err)
			return fmt.Errorf("apply traffic interception rules: %w", err)
		}
	}
	if err := manager.dnsControl.Apply(ctx, dnscontrol.Config{
		DNSNames:  nrptNames,
		DNSServer: manager.config.DNSServer,
		HardenDoH: manager.config.HardenDoH,
	}); err != nil {
		_ = manager.resolver.ApplyPolicy(dnsresolver.Policy{})
		if manager.config.TrafficInterceptionEnabled {
			_ = manager.traffic.Clear(ctx)
		}
		manager.setError(err)
		return fmt.Errorf("apply NRPT rules: %w", err)
	}
	manager.setCatalogApplied(len(nrptNames))
	manager.logger.Info("protected resource catalog applied",
		"catalog_version", catalog.Version,
		"nrpt_rules", len(nrptNames),
		"resources", len(policy.Resources),
		"dns_server", manager.config.DNSServer)
	return nil
}

func (manager *Manager) Clear(ctx context.Context) error {
	if manager == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var errs []error
	if err := manager.resolver.ApplyPolicy(dnsresolver.Policy{}); err != nil {
		errs = append(errs, err)
	}
	if manager.traffic != nil {
		if err := manager.traffic.Clear(ctx); err != nil {
			errs = append(errs, fmt.Errorf("clear traffic interception rules: %w", err))
		}
	}
	if err := manager.dnsControl.Apply(ctx, dnscontrol.Config{}); err != nil {
		errs = append(errs, fmt.Errorf("clear NRPT rules: %w", err))
	}
	if err := errors.Join(errs...); err != nil {
		manager.setError(err)
		return err
	}
	manager.setCatalogApplied(0)
	manager.logger.Info("protected resource DNS rules cleared")
	return nil
}

func (manager *Manager) Status() Status {
	if manager == nil {
		return Status{ResolverState: dnsresolver.StatusWaiting}
	}
	resolverStatus := manager.resolver.Status()
	manager.mu.RLock()
	status := manager.status
	running := manager.running
	manager.mu.RUnlock()
	status.ResolverState = resolverStatus.State
	status.ResourceCount = resolverStatus.ResourceCount
	status.ActiveMappingCount = resolverStatus.ActiveMappingCount
	status.CatalogVersion = resolverStatus.CatalogVersion
	status.PolicyEpoch = resolverStatus.PolicyEpoch
	if resolverStatus.LastError != "" {
		status.LastError = resolverStatus.LastError
	}
	if manager.traffic != nil {
		trafficStatus := manager.traffic.Status()
		status.TrafficState = trafficStatus.State
		status.TrafficProxyAddress = trafficStatus.ProxyLocalAddress
		status.TrafficRuleCount = trafficStatus.RuleCount
		status.WFPRuleState = trafficStatus.WFP.State
		if trafficStatus.LastError != "" {
			status.LastError = trafficStatus.LastError
		}
	}
	if !running && status.LastError == "" && status.ResourceCount > 0 {
		status.LastError = "local DNS resolver is not running"
	}
	return status
}

func (manager *Manager) LookupSyntheticIP(ip string) (dnsresolver.Mapping, bool) {
	if manager == nil || manager.resolver == nil {
		return dnsresolver.Mapping{}, false
	}
	return manager.resolver.Lookup(ip)
}

func (manager *Manager) LocalDNSAddress() string {
	if manager == nil || manager.server == nil {
		return ""
	}
	return manager.server.LocalAddr()
}

func (manager *Manager) waitUntilDNSReady(ctx context.Context) error {
	timer := time.NewTimer(manager.readyTimeout)
	defer timer.Stop()
	select {
	case <-manager.server.Ready():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("local DNS resolver did not become ready")
	}
}

func (manager *Manager) setRunning(running bool) {
	manager.mu.Lock()
	manager.running = running
	manager.mu.Unlock()
}

func (manager *Manager) setError(err error) {
	if err == nil {
		return
	}
	manager.mu.Lock()
	manager.status.LastError = err.Error()
	manager.mu.Unlock()
	manager.logger.Warn("protected resource manager error", "error", err)
}

func (manager *Manager) setCatalogApplied(nrptRuleCount int) {
	manager.mu.Lock()
	manager.status.LastCatalogAppliedAt = time.Now().UTC()
	manager.status.NRPTRuleCount = nrptRuleCount
	manager.status.LastError = ""
	manager.mu.Unlock()
}

func resolverPolicyFromCatalog(catalog ipc.CatalogInfo) dnsresolver.Policy {
	resources := make([]dnsresolver.Resource, 0, len(catalog.Resources))
	for _, resource := range catalog.Resources {
		resources = append(resources, dnsresolver.Resource{
			FQDN:       resource.FQDN,
			ResourceID: resource.ResourceID,
			Protocol:   resource.Protocol,
			Port:       resource.Port,
		})
	}
	return dnsresolver.Policy{
		Version:     catalog.Version,
		PolicyEpoch: catalog.PolicyEpoch,
		Resources:   resources,
		TTLSeconds:  catalog.TTLSeconds,
	}
}

func trafficMappingsFromDNS(mappings []dnsresolver.Mapping) []trafficinterception.ResourceMapping {
	values := make([]trafficinterception.ResourceMapping, 0, len(mappings))
	for _, mapping := range mappings {
		values = append(values, trafficinterception.ResourceMapping{
			ResourceID:  mapping.ResourceID,
			FQDN:        mapping.FQDN,
			Protocol:    mapping.Protocol,
			Port:        mapping.Port,
			SyntheticIP: mapping.SyntheticIP,
		})
	}
	return values
}

func trafficConfigFromConfig(config Config) trafficinterception.Config {
	return trafficinterception.Config{
		Enabled:            config.TrafficInterceptionEnabled,
		ProxyListenAddress: config.TrafficProxyListenAddress,
		WFPDevicePath:      config.WFPDriverDevicePath,
		FailClosed:         config.WFPFailClosed,
		ReadyTimeout:       config.ReadyTimeout,
	}
}

func nrptNamesFromCatalog(catalog ipc.CatalogInfo) []string {
	names := make([]string, 0, len(catalog.Resources))
	for _, resource := range catalog.Resources {
		if host := normalizeHost(resource.FQDN); host != "" {
			names = append(names, host)
		}
	}
	return dnscontrol.NormalizeDNSNames(names)
}

func normalizeConfig(config Config) Config {
	config.DNSListenAddress = strings.TrimSpace(config.DNSListenAddress)
	if config.DNSListenAddress == "" {
		config.DNSListenAddress = dnsresolver.DefaultListenAddress
	}
	config.SyntheticIPCIDR = strings.TrimSpace(config.SyntheticIPCIDR)
	if config.SyntheticIPCIDR == "" {
		config.SyntheticIPCIDR = dnsresolver.DefaultCGNATCIDR
	}
	config.DNSServer = strings.TrimSpace(config.DNSServer)
	if config.DNSServer == "" {
		config.DNSServer = dnsServerFromListenAddress(config.DNSListenAddress)
	}
	return config
}

func dnsServerFromListenAddress(value string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		host = strings.TrimSpace(value)
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return "127.0.0.1"
	}
	return ip.String()
}

func normalizeHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	if value == "" || net.ParseIP(value) != nil || strings.ContainsAny(value, " /\\:\x00") {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || strings.Contains(label, "*") {
			return ""
		}
	}
	return value
}

func firstPositiveDuration(values ...time.Duration) time.Duration {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}
