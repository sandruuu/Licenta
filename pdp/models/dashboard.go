package models

// DashboardStats contains aggregate values shown in the admin dashboard.
type DashboardStats struct {
	TotalUsers     int `json:"total_users"`
	ActiveSessions int `json:"active_sessions"`
	TotalResources int `json:"total_resources"`
	TotalPolicies  int `json:"total_policies"`
	RecentDenials  int `json:"recent_denials"`
	AverageRisk    int `json:"average_risk"`
	HealthyDevices int `json:"healthy_devices"`
	TotalDevices   int `json:"total_devices"`
}
