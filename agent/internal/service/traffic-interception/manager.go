package trafficinterception

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	wfpcontrol "agent/internal/service/wfp-control"
)

const defaultReadyTimeout = 2 * time.Second

type Dependencies struct {
	Logger    *slog.Logger
	WFP       wfpcontrol.Controller
	Connector StreamConnector
	Now       func() time.Time
}

type Manager struct {
	logger     *slog.Logger
	config     Config
	wfp        wfpcontrol.Controller
	proxy      *proxyServer
	readyDelay time.Duration

	mu     sync.RWMutex
	status Status
}

func NewManager(config Config, dependencies Dependencies) (*Manager, error) {
	config = normalizeConfig(config)
	logger := dependencies.Logger
	if logger == nil {
		logger = slog.Default()
	}
	wfp := dependencies.WFP
	if wfp == nil {
		wfp = wfpcontrol.NewController(wfpcontrol.Config{Enabled: config.Enabled, DevicePath: config.WFPDevicePath}, logger)
	}
	proxy := newProxyServer(config, logger, wfp, dependencies.Connector)
	state := StatusDisabled
	if config.Enabled {
		state = StatusStopped
	}
	return &Manager{
		logger:     logger,
		config:     config,
		wfp:        wfp,
		proxy:      proxy,
		readyDelay: firstPositiveDuration(config.ReadyTimeout, defaultReadyTimeout),
		status: Status{
			State:              state,
			ProxyListenAddress: config.ProxyListenAddress,
			WFP:                wfp.Status(),
		},
	}, nil
}

func (manager *Manager) Run(ctx context.Context) error {
	if manager == nil {
		return errors.New("traffic interception manager is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !manager.config.Enabled {
		<-ctx.Done()
		manager.setState(StatusStopped, "")
		return nil
	}
	manager.setState(StatusStarting, "")
	err := manager.proxy.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) && ctx.Err() == nil {
		manager.setState(StatusDegraded, err.Error())
		return err
	}
	manager.setState(StatusStopped, "")
	return nil
}

func (manager *Manager) ApplyMappings(ctx context.Context, mappings []ResourceMapping) error {
	if manager == nil || !manager.config.Enabled {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := manager.waitUntilProxyReady(ctx); err != nil {
		manager.setState(StatusDegraded, err.Error())
		return err
	}
	table, rules, err := newRouteTable(mappings)
	if err != nil {
		manager.setState(StatusDegraded, err.Error())
		return err
	}
	manager.proxy.SetRoutes(table)
	host, port, err := splitHostPort(manager.proxy.LocalAddr())
	if err != nil {
		manager.setState(StatusDegraded, err.Error())
		return err
	}
	if err := manager.wfp.ApplyRules(ctx, wfpcontrol.ApplyRequest{
		ProxyAddress: host,
		ProxyPort:    port,
		ProxyPID:     uint32(os.Getpid()),
		FailClosed:   manager.config.FailClosed,
		Rules:        rules,
	}); err != nil {
		manager.setState(StatusDegraded, err.Error())
		return err
	}
	manager.mu.Lock()
	manager.status.State = StatusReady
	manager.status.ProxyLocalAddress = manager.proxy.LocalAddr()
	manager.status.RuleCount = len(rules)
	manager.status.AcceptedCount = manager.proxy.AcceptedCount()
	manager.status.DeniedCount = manager.proxy.DeniedCount()
	manager.status.LastError = ""
	manager.status.WFP = manager.wfp.Status()
	manager.mu.Unlock()
	manager.logger.Info("traffic interception rules applied", "rules", len(rules), "proxy", manager.proxy.LocalAddr())
	return nil
}

func (manager *Manager) Clear(ctx context.Context) error {
	if manager == nil || !manager.config.Enabled {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	manager.proxy.SetRoutes(routeTable{byDestination: map[string]route{}})
	if err := manager.wfp.Clear(ctx); err != nil {
		manager.setState(StatusDegraded, err.Error())
		return err
	}
	manager.mu.Lock()
	manager.status.RuleCount = 0
	manager.status.LastError = ""
	manager.status.WFP = manager.wfp.Status()
	manager.mu.Unlock()
	return nil
}

func (manager *Manager) Status() Status {
	if manager == nil {
		return Status{State: StatusDisabled}
	}
	manager.mu.RLock()
	status := manager.status
	manager.mu.RUnlock()
	if manager.proxy != nil {
		status.ProxyLocalAddress = manager.proxy.LocalAddr()
		status.RuleCount = manager.proxy.RouteCount()
		status.AcceptedCount = manager.proxy.AcceptedCount()
		status.DeniedCount = manager.proxy.DeniedCount()
	}
	if manager.wfp != nil {
		status.WFP = manager.wfp.Status()
	}
	return status
}

func (manager *Manager) waitUntilProxyReady(ctx context.Context) error {
	timer := time.NewTimer(manager.readyDelay)
	defer timer.Stop()
	select {
	case <-manager.proxy.Ready():
		if manager.proxy.LocalAddr() == "" {
			return errors.New("local traffic proxy is not listening")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("local traffic proxy did not become ready")
	}
}

func (manager *Manager) setState(state, lastError string) {
	manager.mu.Lock()
	manager.status.State = state
	manager.status.LastError = lastError
	if manager.proxy != nil {
		manager.status.ProxyLocalAddress = manager.proxy.LocalAddr()
		manager.status.RuleCount = manager.proxy.RouteCount()
		manager.status.AcceptedCount = manager.proxy.AcceptedCount()
		manager.status.DeniedCount = manager.proxy.DeniedCount()
	}
	if manager.wfp != nil {
		manager.status.WFP = manager.wfp.Status()
	}
	manager.mu.Unlock()
}

func normalizeConfig(config Config) Config {
	config.ProxyListenAddress = strings.TrimSpace(config.ProxyListenAddress)
	if config.ProxyListenAddress == "" {
		config.ProxyListenAddress = DefaultProxyListenAddress
	}
	config.WFPDevicePath = strings.TrimSpace(config.WFPDevicePath)
	if config.WFPDevicePath == "" {
		config.WFPDevicePath = wfpcontrol.DefaultDevicePath
	}
	return config
}

func splitHostPort(value string) (string, int, error) {
	host, portValue, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return "", 0, fmt.Errorf("proxy address %q is not host:port: %w", value, err)
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("proxy address %q has invalid port", value)
	}
	return strings.Trim(host, "[]"), port, nil
}

func firstPositiveDuration(values ...time.Duration) time.Duration {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}
