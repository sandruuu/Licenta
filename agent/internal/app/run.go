package app

import (
	"context"
	"log/slog"
	"os"

	"ztna.local/agent/internal/bootstrap"
	"ztna.local/agent/internal/meta"
	"ztna.local/agent/internal/service"
	"ztna.local/agent/internal/service/scm"
	"ztna.local/agent/internal/tray"
)

func Run(ctx context.Context, args []string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	options, err := Parse(args)
	if err != nil {
		return err
	}
	if options.Command == CommandHelp {
		PrintUsage(os.Stdout)
		return nil
	}

	svc := service.New(service.Options{
		AuthorizedUserSID: options.AuthorizedUserSID,
		CloudIssuer:       options.CloudIssuer,
		CloudURL:          options.CloudURL,
		CloudCertSHA256:   options.CloudCertSHA256,
		JWKSURL:           options.JWKSURL,
		CAFile:            options.CAFile,
		DNSServer:         options.DNSServer,
		CatalogInterval:   options.CatalogInterval,
		TUNEnabled:        options.TUNEnabled,
		TUNName:           options.TUNName,
		TUNIP:             options.TUNIP,
		TUNNetmask:        options.TUNNetmask,
		TUNRouteCIDR:      options.TUNRouteCIDR,
		GatewayTunnel:     options.GatewayTunnel,
		GatewayAddress:    options.GatewayAddress,
		GatewayServerName: options.GatewayServerName,
		ProcessIdentity:   options.ProcessIdentity,
		Logger:            logger,
	})
	switch options.Command {
	case CommandBootstrap:
		return bootstrap.Run(ctx, bootstrap.Options{DemoMessage: options.DemoMessage, Timeout: options.Timeout, CloudIssuer: options.CloudIssuer, JWKSURL: options.JWKSURL, CAFile: options.CAFile, DNSServer: options.DNSServer, CatalogInterval: options.CatalogInterval, TUNEnabled: options.TUNEnabled, TUNName: options.TUNName, TUNIP: options.TUNIP, TUNNetmask: options.TUNNetmask, TUNRouteCIDR: options.TUNRouteCIDR, GatewayTunnel: options.GatewayTunnel, GatewayAddress: options.GatewayAddress, GatewayServerName: options.GatewayServerName, ProcessIdentity: options.ProcessIdentity, Login: options.Login, CloudURL: options.CloudURL, IssuerURL: options.IssuerURL, ClientID: options.ClientID, Scopes: options.Scopes, DeviceID: options.DeviceID, EnrollmentNonce: options.EnrollmentNonce, KeyName: options.KeyName, Hostname: options.Hostname, ACRValues: options.ACRValues}, logger)
	case CommandService:
		return scm.RunService(meta.ServiceName, svc.Run, logger)
	case CommandRunService:
		return service.RunConsole(ctx, svc)
	case CommandInstallService:
		if err := scm.InstallOrUpdate(scm.Config{
			ServiceName:       meta.ServiceName,
			DisplayName:       meta.ServiceDisplayName,
			Description:       meta.ServiceDescription,
			AuthorizedUserSID: options.AuthorizedUserSID,
			CloudIssuer:       options.CloudIssuer,
			CloudURL:          options.CloudURL,
			CloudCertSHA256:   options.CloudCertSHA256,
			JWKSURL:           options.JWKSURL,
			CAFile:            options.CAFile,
			DNSServer:         options.DNSServer,
			CatalogInterval:   options.CatalogInterval,
			TUNEnabled:        options.TUNEnabled,
			TUNName:           options.TUNName,
			TUNIP:             options.TUNIP,
			TUNNetmask:        options.TUNNetmask,
			TUNRouteCIDR:      options.TUNRouteCIDR,
			GatewayTunnel:     options.GatewayTunnel,
			GatewayAddress:    options.GatewayAddress,
			GatewayServerName: options.GatewayServerName,
			ProcessIdentity:   options.ProcessIdentity,
		}, logger); err != nil {
			return err
		}
		return scm.Start(meta.ServiceName, logger)
	case CommandStart:
		return scm.Start(meta.ServiceName, logger)
	case CommandStop:
		return scm.Stop(meta.ServiceName, logger)
	case CommandStatus:
		return scm.PrintStatus(meta.ServiceName)
	case CommandUninstall:
		return scm.Uninstall(meta.ServiceName, logger)
	case CommandTray:
		return tray.Run(ctx, tray.Options{GUI: !options.TrayProof, Message: options.DemoMessage, Stay: options.TrayStay, Timeout: options.Timeout, Login: options.Login, CloudURL: options.CloudURL, IssuerURL: options.IssuerURL, ClientID: options.ClientID, Scopes: options.Scopes, DeviceID: options.DeviceID, Nonce: options.EnrollmentNonce, UserSID: options.AuthorizedUserSID, KeyName: options.KeyName, Hostname: options.Hostname, CAFile: options.CAFile, ACRValues: options.ACRValues}, logger)
	default:
		return ErrUsage
	}
}
