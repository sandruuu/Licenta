//go:build windows

package enrollment

import (
	"context"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	certStoreProviderSystemW    = 10
	x509ASNEncoding             = 0x00000001
	pkcs7ASNEncoding            = 0x00010000
	certEncoding                = x509ASNEncoding | pkcs7ASNEncoding
	certSystemStoreLocalMachine = 0x00020000
	certStoreOpenExistingFlag   = 0x00004000
	certStoreAddReplaceExisting = 3
	certKeyProvInfoPropertyID   = 2
	certNCryptKeySpec           = 0xffffffff
	certMachineKeysetFlag       = 0x00000020
	localMachineMyStoreName     = "MY"
	localMachineCAStoreName     = "CA"
)

var (
	crypt32                               = windows.NewLazySystemDLL("crypt32.dll")
	procCertOpenStore                     = crypt32.NewProc("CertOpenStore")
	procCertCloseStore                    = crypt32.NewProc("CertCloseStore")
	procCertAddEncodedCertificateToStore  = crypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertFreeCertificateContext        = crypt32.NewProc("CertFreeCertificateContext")
	procCertSetCertificateContextProperty = crypt32.NewProc("CertSetCertificateContextProperty")
)

type MachineStoreInstaller struct{}

type certStoreHandle uintptr
type certContext uintptr

type cryptKeyProvInfo struct {
	ContainerName  *uint16
	ProviderName   *uint16
	ProviderType   uint32
	Flags          uint32
	ProviderParams uint32
	Params         uintptr
	KeySpec        uint32
}

func NewDefaultCertificateInstaller() CertificateInstaller {
	return MachineStoreInstaller{}
}

func (MachineStoreInstaller) InstallCertificate(ctx context.Context, request InstallRequest) (InstallResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return InstallResult{}, ctx.Err()
	default:
	}
	leafDERs, err := certificateDERs(request.CertPEM)
	if err != nil {
		return InstallResult{}, err
	}
	if len(leafDERs) == 0 {
		return InstallResult{}, fmt.Errorf("leaf certificate is required")
	}
	myStore, err := openSystemCertStore(localMachineMyStoreName)
	if err != nil {
		return InstallResult{}, err
	}
	defer closeCertStore(myStore)
	leafContext, err := addCertificate(myStore, leafDERs[0])
	if err != nil {
		return InstallResult{}, err
	}
	defer freeCertContext(leafContext)
	if strings.TrimSpace(request.KeyName) != "" {
		provider := strings.TrimSpace(request.KeyProvider)
		if provider == "" {
			provider = "Microsoft Platform Crypto Provider"
		}
		if err := setCertificateKeyProviderInfo(leafContext, request.KeyName, provider); err != nil {
			return InstallResult{}, err
		}
	}

	if strings.TrimSpace(string(request.CAPEM)) != "" {
		caDERs, err := certificateDERs(request.CAPEM)
		if err != nil {
			return InstallResult{}, err
		}
		caStore, err := openSystemCertStore(localMachineCAStoreName)
		if err != nil {
			return InstallResult{}, err
		}
		defer closeCertStore(caStore)
		for _, der := range caDERs {
			caContext, err := addCertificate(caStore, der)
			if err != nil {
				return InstallResult{}, err
			}
			freeCertContext(caContext)
		}
	}
	return InstallResult{Installed: true, LeafStore: `LocalMachine\My`, CAStore: `LocalMachine\CA`}, nil
}

func openSystemCertStore(name string) (certStoreHandle, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	store, _, callErr := procCertOpenStore.Call(
		certStoreProviderSystemW,
		certEncoding,
		0,
		certSystemStoreLocalMachine|certStoreOpenExistingFlag,
		uintptr(unsafe.Pointer(namePtr)),
	)
	if store == 0 {
		if callErr != windows.ERROR_SUCCESS {
			return 0, callErr
		}
		return 0, fmt.Errorf("open certificate store %s", name)
	}
	return certStoreHandle(store), nil
}

func addCertificate(store certStoreHandle, der []byte) (certContext, error) {
	if len(der) == 0 {
		return 0, fmt.Errorf("certificate DER is required")
	}
	var context uintptr
	ok, _, callErr := procCertAddEncodedCertificateToStore.Call(
		uintptr(store),
		certEncoding,
		uintptr(unsafe.Pointer(&der[0])),
		uintptr(uint32(len(der))),
		certStoreAddReplaceExisting,
		uintptr(unsafe.Pointer(&context)),
	)
	if ok == 0 {
		if callErr != windows.ERROR_SUCCESS {
			return 0, callErr
		}
		return 0, fmt.Errorf("add certificate to store")
	}
	return certContext(context), nil
}

func setCertificateKeyProviderInfo(context certContext, keyName, providerName string) error {
	containerPtr, err := windows.UTF16PtrFromString(strings.TrimSpace(keyName))
	if err != nil {
		return err
	}
	providerPtr, err := windows.UTF16PtrFromString(strings.TrimSpace(providerName))
	if err != nil {
		return err
	}
	info := cryptKeyProvInfo{
		ContainerName: containerPtr,
		ProviderName:  providerPtr,
		ProviderType:  0,
		Flags:         certMachineKeysetFlag,
		KeySpec:       certNCryptKeySpec,
	}
	ok, _, callErr := procCertSetCertificateContextProperty.Call(
		uintptr(context),
		certKeyProvInfoPropertyID,
		0,
		uintptr(unsafe.Pointer(&info)),
	)
	if ok == 0 {
		if callErr != windows.ERROR_SUCCESS {
			return callErr
		}
		return fmt.Errorf("set certificate key provider info")
	}
	return nil
}

func closeCertStore(store certStoreHandle) {
	if store != 0 {
		_, _, _ = procCertCloseStore.Call(uintptr(store), 0)
	}
}

func freeCertContext(context certContext) {
	if context != 0 {
		_, _, _ = procCertFreeCertificateContext.Call(uintptr(context))
	}
}
