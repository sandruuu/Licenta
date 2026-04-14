package main

// HealthCheck represents a single device health check result
type HealthCheck struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"` // "good", "warning", "critical"
	Description string            `json:"description"`
	Details     map[string]string `json:"details"`
}

// DeviceHealth is the aggregate device health report
type DeviceHealth struct {
	Hostname     string        `json:"hostname"`
	OS           string        `json:"os"`
	Checks       []HealthCheck `json:"checks"`
	OverallScore int           `json:"overallScore"`
	CollectedAt  string        `json:"collectedAt"`
}
