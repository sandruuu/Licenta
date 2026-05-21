package deviceposture

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"licenta/features/contracts"
)

const defaultCollectorBudget = 10 * time.Second

type Collector struct {
	CollectorBudget time.Duration
	Now             func() time.Time
}

func NewCollector() *Collector {
	return &Collector{CollectorBudget: defaultCollectorBudget, Now: time.Now}
}

func (collector *Collector) Collect(ctx context.Context, deviceID string) (contracts.DevicePostureReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	budget := defaultCollectorBudget
	if collector != nil && collector.CollectorBudget > 0 {
		budget = collector.CollectorBudget
	}
	now := time.Now
	if collector != nil && collector.Now != nil {
		now = collector.Now
	}
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "Unknown"
	}

	checks, osTag := collectChecks(ctx, budget, platformCheckDefinitions())
	if strings.TrimSpace(osTag) == "" {
		osTag = "windows"
	}

	return contracts.DevicePostureReport{
		DeviceID:    strings.TrimSpace(deviceID),
		Hostname:    hostname,
		OS:          osTag,
		Checks:      checks,
		CollectedAt: now().UTC(),
	}, nil
}

type checkDefinition struct {
	Name  string
	Build func(context.Context) (contracts.DevicePostureCheck, string)
}

func collectChecks(ctx context.Context, budget time.Duration, definitions []checkDefinition) ([]contracts.DevicePostureCheck, string) {
	if len(definitions) == 0 {
		return nil, ""
	}
	checks := make([]contracts.DevicePostureCheck, len(definitions))
	osTags := make([]string, len(definitions))
	var waitGroup sync.WaitGroup
	for index, definition := range definitions {
		index := index
		definition := definition
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			check, osTag := runCheck(ctx, budget, definition.Name, definition.Build)
			checks[index] = check
			osTags[index] = osTag
		}()
	}
	waitGroup.Wait()
	for _, osTag := range osTags {
		if strings.TrimSpace(osTag) != "" {
			return checks, osTag
		}
	}
	return checks, ""
}

func runCheck(ctx context.Context, budget time.Duration, name string, build func(context.Context) (contracts.DevicePostureCheck, string)) (contracts.DevicePostureCheck, string) {
	if budget <= 0 {
		budget = defaultCollectorBudget
	}
	checkContext, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	type result struct {
		check contracts.DevicePostureCheck
		osTag string
	}
	results := make(chan result, 1)
	go func() {
		check, osTag := build(checkContext)
		results <- result{check: check, osTag: osTag}
	}()
	select {
	case result := <-results:
		return result.check, result.osTag
	case <-checkContext.Done():
		return contracts.DevicePostureCheck{
			Name:        name,
			Status:      contracts.DevicePostureStatusUnavailable,
			Description: fmt.Sprintf("Collector did not complete within %s", budget),
			Details: map[string]string{
				"timeout": budget.String(),
			},
		}, ""
	}
}

func boolToOnOff(value bool) string {
	if value {
		return "ON"
	}
	return "OFF"
}

func boolToYesNo(value bool) string {
	if value {
		return "Yes"
	}
	return "No"
}

func boolToStatus(value bool, trueValue, falseValue string) string {
	if value {
		return trueValue
	}
	return falseValue
}
