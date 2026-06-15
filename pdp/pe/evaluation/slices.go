package evaluation

import "strings"

func containsString(slice []string, item string) bool {
	item = strings.TrimSpace(item)
	if item == "" {
		return false
	}
	for _, s := range slice {
		if strings.EqualFold(strings.TrimSpace(s), item) {
			return true
		}
	}
	return false
}

func containsAnyString(slice []string, candidates ...string) bool {
	for _, candidate := range candidates {
		if containsString(slice, candidate) {
			return true
		}
	}
	return false
}

func intersectsString(left, right []string) bool {
	for _, candidate := range right {
		if containsString(left, candidate) {
			return true
		}
	}
	return false
}

func containsInt(slice []int, item int) bool {
	for _, i := range slice {
		if i == item {
			return true
		}
	}
	return false
}
