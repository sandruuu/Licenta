//go:build windows

package dnscontrol

import (
	"context"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	dnsPolicyConfigPath = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	chromePolicyPath    = `SOFTWARE\Policies\Google\Chrome`
	edgePolicyPath      = `SOFTWARE\Policies\Microsoft\Edge`
	firefoxDoHPath      = `SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`
)

func applyPlatform(ctx context.Context, config Config) error {
	if err := applyNRPT(config.DNSSuffixes, config.DNSServer); err != nil {
		return err
	}
	if config.HardenDoH {
		if err := applyDoHPolicies(); err != nil {
			return err
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	_ = exec.CommandContext(ctx, "ipconfig", "/flushdns").Run()
	return nil
}

func applyNRPT(suffixes []string, dnsServer string) error {
	base, _, err := registry.CreateKey(registry.LOCAL_MACHINE, dnsPolicyConfigPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer base.Close()

	desired := make(map[string]struct{}, len(suffixes))
	for _, suffix := range suffixes {
		keyName := RuleKey(suffix)
		if keyName == "" {
			continue
		}
		desired[keyName] = struct{}{}
		key, _, err := registry.CreateKey(base, keyName, registry.ALL_ACCESS)
		if err != nil {
			return err
		}
		if err := key.SetStringsValue("Name", []string{nrptNameValue(suffix)}); err != nil {
			key.Close()
			return err
		}
		if err := key.SetStringValue("GenericDNSServers", dnsServer); err != nil {
			key.Close()
			return err
		}
		if err := key.SetDWordValue("ConfigOptions", 0x8); err != nil {
			key.Close()
			return err
		}
		if err := key.SetDWordValue("Version", 0x2); err != nil {
			key.Close()
			return err
		}
		key.Close()
	}

	existing, err := base.ReadSubKeyNames(-1)
	if err != nil {
		return err
	}
	for _, keyName := range existing {
		if !strings.HasPrefix(keyName, "ZTNA-") {
			continue
		}
		if _, ok := desired[keyName]; !ok {
			_ = registry.DeleteKey(base, keyName)
		}
	}
	return nil
}

func applyDoHPolicies() error {
	if err := setBrowserDoHOff(chromePolicyPath); err != nil {
		return err
	}
	if err := setBrowserDoHOff(edgePolicyPath); err != nil {
		return err
	}
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, firefoxDoHPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()
	if err := key.SetDWordValue("Enabled", 0); err != nil {
		return err
	}
	return key.SetDWordValue("Locked", 1)
}

func setBrowserDoHOff(path string) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue("DnsOverHttpsMode", "off")
}
