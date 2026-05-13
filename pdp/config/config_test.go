package config

import "testing"

func TestLoadProjectConfig(t *testing.T) {
	if _, err := LoadFromFile("../config.json"); err != nil {
		t.Fatalf("LoadFromFile failed for project config.json: %v", err)
	}
}
