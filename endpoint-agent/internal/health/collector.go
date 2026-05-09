package health

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"ztna.local/endpoint-agent/internal/ipc"
)

const defaultCollectorBudget = 10 * time.Second

var healthCheckWeights = map[string]int{
	"Firewall":         25,
	"Antivirus":        25,
	"Disk Encryption":  20,
	"Password & Lock":  15,
	"Operating System": 15,
}

type Collector struct {
	CollectorBudget time.Duration
	Now             func() time.Time
}

func NewCollector() *Collector {
	return &Collector{CollectorBudget: defaultCollectorBudget, Now: time.Now}
}

func (collector *Collector) Collect(ctx context.Context, deviceID string) (ipc.HealthReport, error) {
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
		osTag = runtime.GOOS
	}

	return ipc.HealthReport{
		DeviceID:     strings.TrimSpace(deviceID),
		Hostname:     hostname,
		OS:           osTag,
		Checks:       checks,
		OverallScore: CalculateScore(checks),
		CollectedAt:  now().UTC(),
	}, nil
}

type checkDefinition struct {
	Name  string
	Build func(context.Context) (ipc.HealthCheck, string)
}

func collectChecks(ctx context.Context, budget time.Duration, definitions []checkDefinition) ([]ipc.HealthCheck, string) {
	if len(definitions) == 0 {
		return nil, ""
	}
	checks := make([]ipc.HealthCheck, len(definitions))
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

func runCheck(ctx context.Context, budget time.Duration, name string, build func(context.Context) (ipc.HealthCheck, string)) (ipc.HealthCheck, string) {
	if budget <= 0 {
		budget = defaultCollectorBudget
	}
	checkContext, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	type result struct {
		check ipc.HealthCheck
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
		return ipc.HealthCheck{
			Name:        name,
			Status:      "warning",
			Description: fmt.Sprintf("Collector did not complete within %s", budget),
			Details: map[string]string{
				"timeout": budget.String(),
			},
		}, ""
	}
}

func CalculateScore(checks []ipc.HealthCheck) int {
	if len(checks) == 0 {
		return 0
	}
	weightedScore := 0
	totalWeight := 0
	for _, check := range checks {
		weight, ok := healthCheckWeights[check.Name]
		if !ok {
			continue
		}
		weightedScore += statusScore(check.Status) * weight
		totalWeight += weight
	}
	if totalWeight > 0 {
		return weightedScore / totalWeight
	}
	score := 0
	for _, check := range checks {
		score += statusScore(check.Status)
	}
	return score / len(checks)
}

func statusScore(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "good":
		return 100
	case "warning":
		return 50
	case "critical":
		return 0
	default:
		return 0
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
