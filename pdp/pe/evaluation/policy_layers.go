package evaluation

import (
	"strings"

	"pdp/models"
)

const (
	policyLayerResourceGroup = 1
	policyLayerResource      = 2
	policyLayerGroup         = 3
	policyLayerOrganization  = 4
)

func policyLayerPriority(rule *models.PolicyRule) int {
	layer := policyLayerOrganization
	if rule == nil {
		return layer
	}
	for _, assignment := range rule.Assignments {
		if assignment == nil {
			continue
		}
		if candidate := assignmentLayerPriority(assignment); candidate < layer {
			layer = candidate
		}
	}
	return layer
}

func assignmentLayerPriority(assignment *models.PolicyAssignment) int {
	level := strings.ToLower(strings.TrimSpace(assignment.Level))
	hasResource := strings.TrimSpace(assignment.ResourceID) != ""
	hasGroup := strings.TrimSpace(assignment.GroupID) != "" || strings.TrimSpace(assignment.GroupName) != ""
	if level == "" || (level == "organization" && (hasResource || hasGroup)) {
		switch {
		case hasResource && hasGroup:
			return policyLayerResourceGroup
		case hasResource:
			return policyLayerResource
		case hasGroup:
			return policyLayerGroup
		default:
			return policyLayerOrganization
		}
	}
	switch level {
	case "resource_group":
		return policyLayerResourceGroup
	case "resource":
		return policyLayerResource
	case "group":
		return policyLayerGroup
	default:
		return policyLayerOrganization
	}
}
