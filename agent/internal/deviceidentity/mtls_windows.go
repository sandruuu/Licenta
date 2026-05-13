//go:build windows

package deviceidentity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	machineCertStoreProviderSystemW    = 10
	machineX509ASNEncoding             = 0x00000001
	machinePKCS7ASNEncoding            = 0x00010000
	machineCertEncoding                = machineX509ASNEncoding | machinePKCS7ASNEncoding
	machineCertSystemStoreLocalMachine = 0x00020000
	machineCertStoreOpenExistingFlag   = 0x00004000
	machineMyStoreName                 = "MY"
	machineCAStoreName                 = "CA"
)

func LoadMachineTLSCertificate(ctx context.Context, options MachineCertificateOptions) (tls.Certificate, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return tls.Certificate{}, ctx.Err()
	default:
	}

	options, err := validateMachineCertificateOptions(options)
	if err != nil {
		return tls.Certificate{}, err
	}
	signer, err := NewKeyStore().OpenSigningKey(ctx, options.KeyName)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("open endpoint signing key: %w", err)
	}
	leafCandidates, err := machineStoreCertificates(machineMyStoreName)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := selectMachineCertificate(leafCandidates, options.DeviceID, signer.Public(), options.Clock().UTC())
	if err != nil {
		return tls.Certificate{}, err
	}
	issuers, err := machineStoreCertificates(machineCAStoreName)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tlsCertificateFromMachineStore(signer, leaf, issuers), nil
}

func machineStoreCertificates(name string) ([]*x509.Certificate, error) {
	store, err := openMachineCertStore(name)
	if err != nil {
		return nil, err
	}
	defer closeMachineCertStore(store)

	certs := []*x509.Certificate{}
	var current *windows.CertContext
	for {
		next, _ := windows.CertEnumCertificatesInStore(store, current)
		if next == nil {
			break
		}
		current = next
		if current.EncodedCert == nil || current.Length == 0 {
			continue
		}
		der := unsafe.Slice(current.EncodedCert, int(current.Length))
		cert, err := x509.ParseCertificate(append([]byte(nil), der...))
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func openMachineCertStore(name string) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	store, err := windows.CertOpenStore(
		uintptr(machineCertStoreProviderSystemW),
		machineCertEncoding,
		0,
		machineCertSystemStoreLocalMachine|machineCertStoreOpenExistingFlag,
		uintptr(unsafe.Pointer(namePtr)),
	)
	if err != nil {
		return 0, err
	}
	if store == 0 {
		return 0, fmt.Errorf("open certificate store LocalMachine\\%s", name)
	}
	return store, nil
}

func closeMachineCertStore(store windows.Handle) {
	if store != 0 {
		_ = windows.CertCloseStore(store, 0)
	}
}
