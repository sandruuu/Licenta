//go:build windows

package dnscontrol

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const (
	dnsClientPolicyPath = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`
	dnsPolicyConfigName = `DnsPolicyConfig`
	dnsPolicyConfigPath = dnsClientPolicyPath + `\` + dnsPolicyConfigName
	chromePolicyPath    = `SOFTWARE\Policies\Google\Chrome`
	edgePolicyPath      = `SOFTWARE\Policies\Microsoft\Edge`
	firefoxDoHPath      = `SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`
	nrptRulePrefix      = "TRUSTAGENT-"
	nrptRuleComment     = "TRUSTAGENT"
)

func applyPlatform(ctx context.Context, config Config) error {
	if err := applyNRPT(ctx, config.DNSNames, config.DNSServer); err != nil {
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

func applyNRPT(ctx context.Context, names []string, dnsServer string) error {
	if err := deleteLegacyNRPTKeys(); err != nil {
		return err
	}
	return applyNRPTWithCmdlets(ctx, names, dnsServer)
}

func applyNRPTWithCmdlets(ctx context.Context, names []string, dnsServer string) error {
	var script strings.Builder
	script.WriteString("$ErrorActionPreference = 'Stop'\n")
	script.WriteString("Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -eq '")
	script.WriteString(nrptRuleComment)
	script.WriteString("' -or $_.DisplayName -like '")
	script.WriteString(nrptRulePrefix)
	script.WriteString("*' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }\n")
	if len(names) > 0 {
		script.WriteString("Set-DnsClientNrptGlobal -EnableDAForAllNetworks EnableAlways -QueryPolicy QueryBoth -SecureNameQueryFallback FallbackPrivate\n")
	}
	for _, name := range names {
		keyName := RuleKey(name)
		if keyName == "" {
			continue
		}
		script.WriteString("Add-DnsClientNrptRule -Namespace ")
		script.WriteString(powerShellString(nrptNameValue(name)))
		script.WriteString(" -NameServers ")
		script.WriteString(powerShellString(dnsServer))
		script.WriteString(" -DisplayName ")
		script.WriteString(powerShellString(keyName))
		script.WriteString(" -Comment '")
		script.WriteString(nrptRuleComment)
		script.WriteString("' | Out-Null\n")
	}
	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script.String()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply NRPT rules: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func deleteLegacyNRPTKeys() error {
	base, err := registry.OpenKey(registry.LOCAL_MACHINE, dnsPolicyConfigPath, registry.ALL_ACCESS)
	if err != nil {
		if err == syscall.ERROR_FILE_NOT_FOUND {
			return nil
		}
		return err
	}

	existing, err := base.ReadSubKeyNames(-1)
	if err != nil {
		base.Close()
		return err
	}
	for _, keyName := range existing {
		if !strings.HasPrefix(keyName, nrptRulePrefix) {
			continue
		}
		if err := registry.DeleteKey(base, keyName); err != nil {
			base.Close()
			return err
		}
	}
	if err := deleteEmptyLegacyNRPTKey(base); err != nil {
		return err
	}
	return nil
}

func deleteEmptyLegacyNRPTKey(base registry.Key) error {
	subkeys, err := base.ReadSubKeyNames(-1)
	if err != nil {
		base.Close()
		return err
	}
	values, err := base.ReadValueNames(-1)
	if err != nil {
		base.Close()
		return err
	}
	if len(subkeys) > 0 || len(values) > 0 {
		return base.Close()
	}
	if err := base.Close(); err != nil {
		return err
	}
	parent, err := registry.OpenKey(registry.LOCAL_MACHINE, dnsClientPolicyPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer parent.Close()
	err = registry.DeleteKey(parent, dnsPolicyConfigName)
	if err == syscall.ERROR_FILE_NOT_FOUND {
		return nil
	}
	return err
}

func powerShellString(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
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
