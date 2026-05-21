//go:build windows

package enrollment

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"agent/internal/shared/ipc"
)

const (
	msPlatformCryptoProvider = "Microsoft Platform Crypto Provider"
	msSoftwareKSPProvider    = "Microsoft Software Key Storage Provider"
	ncryptRSAAlgorithm       = "RSA"
	ncryptLengthProperty     = "Length"
	ncryptExportPolicy       = "Export Policy"
	bcryptRSAPublicBlob      = "RSAPUBLICBLOB"
	bcryptPadPKCS1           = 0x2
	ncryptMachineKeyFlag     = 0x20
	ncryptSilentFlag         = 0x40
	certKeyProvInfoPropID    = 2
	cryptMachineKeyset       = 0x20
)

var (
	ncryptDLL                     = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = ncryptDLL.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey             = ncryptDLL.NewProc("NCryptOpenKey")
	procNCryptCreatePersistedKey  = ncryptDLL.NewProc("NCryptCreatePersistedKey")
	procNCryptSetProperty         = ncryptDLL.NewProc("NCryptSetProperty")
	procNCryptFinalizeKey         = ncryptDLL.NewProc("NCryptFinalizeKey")
	procNCryptExportKey           = ncryptDLL.NewProc("NCryptExportKey")
	procNCryptSignHash            = ncryptDLL.NewProc("NCryptSignHash")
	procNCryptFreeObject          = ncryptDLL.NewProc("NCryptFreeObject")
	crypt32DLL                    = windows.NewLazySystemDLL("crypt32.dll")
	procCertSetContextProperty    = crypt32DLL.NewProc("CertSetCertificateContextProperty")
)

type windowsDeviceIdentity struct{}

func NewDefaultDeviceIdentity() DeviceIdentity {
	return windowsDeviceIdentity{}
}

func (identity windowsDeviceIdentity) CreateEnrollmentCSR(ctx context.Context, keyName string) (EnrollmentCSR, error) {
	signer, err := ensureNCryptSigner(strings.TrimSpace(keyName))
	if err != nil {
		return EnrollmentCSR{}, err
	}
	defer signer.Close()
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "TrustAgent Device Enrollment"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, signer)
	if err != nil {
		return EnrollmentCSR{}, fmt.Errorf("create enrollment CSR: %w", err)
	}
	parsed, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return EnrollmentCSR{}, fmt.Errorf("parse generated CSR: %w", err)
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		return EnrollmentCSR{}, err
	}
	return EnrollmentCSR{
		KeyName:     signer.keyName,
		Provider:    signer.providerName,
		CSRPEM:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		CSRDER:      csrDER,
		SPKIDER:     parsed.RawSubjectPublicKeyInfo,
		CSRHash:     sha256Hex(csrDER),
		SPKIHash:    sha256Hex(parsed.RawSubjectPublicKeyInfo),
		DeviceNonce: nonce,
	}, nil
}

func (identity windowsDeviceIdentity) SignEnrollmentProof(ctx context.Context, keyName string, payload []byte) ([]byte, error) {
	signer, err := ensureNCryptSigner(strings.TrimSpace(keyName))
	if err != nil {
		return nil, err
	}
	defer signer.Close()
	digest := sha256.Sum256(payload)
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign enrollment proof: %w", err)
	}
	return signature, nil
}

func (identity windowsDeviceIdentity) InstallDeviceCertificate(ctx context.Context, request InstallCertificateRequest) (InstalledCertificate, error) {
	certDER, err := firstPEMCertificate(request.CertificatePEM)
	if err != nil {
		return InstalledCertificate{}, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return InstalledCertificate{}, fmt.Errorf("parse issued certificate: %w", err)
	}
	context, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, &certDER[0], uint32(len(certDER)))
	if err != nil {
		return InstalledCertificate{}, fmt.Errorf("create certificate context: %w", err)
	}
	defer windows.CertFreeCertificateContext(context)
	if err := setCertificateKeyProviderInfo(context, request.KeyName, request.KeyProvider); err != nil {
		return InstalledCertificate{}, err
	}
	store, err := openLocalMachineMyStore()
	if err != nil {
		return InstalledCertificate{}, err
	}
	defer windows.CertCloseStore(store, 0)
	var added *windows.CertContext
	if err := windows.CertAddCertificateContextToStore(store, context, windows.CERT_STORE_ADD_REPLACE_EXISTING, &added); err != nil {
		return InstalledCertificate{}, fmt.Errorf("add certificate to LocalMachine\\My: %w", err)
	}
	if added != nil {
		_ = windows.CertFreeCertificateContext(added)
	}
	return InstalledCertificate{Thumbprint: sha256Hex(certDER), ExpiresAt: cert.NotAfter.UTC()}, nil
}

func (identity windowsDeviceIdentity) CheckLocalEnrollment(ctx context.Context, record EnrollmentRecord) (LocalEnrollmentCheck, error) {
	if record.EnrollmentState != ipc.EnrollmentStateEnrolled && record.EnrollmentState != "" {
		return LocalEnrollmentCheck{Enrolled: false, Reason: "enrollment state is not enrolled"}, nil
	}
	if strings.TrimSpace(record.DeviceKeyName) == "" {
		return LocalEnrollmentCheck{Enrolled: false, Reason: "device key name is missing"}, nil
	}
	signer, err := openNCryptSigner(strings.TrimSpace(record.DeviceKeyName))
	if err != nil {
		return LocalEnrollmentCheck{Enrolled: false, Reason: "device key is missing"}, nil
	}
	signer.Close()
	cert, certContext, err := findCertificateByThumbprint(strings.TrimSpace(record.DeviceCertThumbprint))
	if err != nil {
		return LocalEnrollmentCheck{}, err
	}
	if certContext == nil || cert == nil {
		return LocalEnrollmentCheck{Enrolled: false, Reason: "device certificate is missing"}, nil
	}
	defer windows.CertFreeCertificateContext(certContext)
	if time.Now().UTC().After(cert.NotAfter.UTC()) {
		return LocalEnrollmentCheck{Enrolled: false, Reason: "device certificate is expired"}, nil
	}
	if !certificateAllowsClientAuth(cert) {
		return LocalEnrollmentCheck{Enrolled: false, Reason: "device certificate is missing clientAuth EKU"}, nil
	}
	if err := acquireCertificatePrivateKey(certContext); err != nil {
		return LocalEnrollmentCheck{Enrolled: false, Reason: "certificate is not associated with the local private key"}, nil
	}
	return LocalEnrollmentCheck{Enrolled: true}, nil
}

func (identity windowsDeviceIdentity) ClientCertificate(ctx context.Context, record EnrollmentRecord) (tls.Certificate, func(), error) {
	cert, certContext, err := findCertificateByThumbprint(strings.TrimSpace(record.DeviceCertThumbprint))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if cert == nil || certContext == nil {
		return tls.Certificate{}, nil, fmt.Errorf("device certificate is missing")
	}
	windows.CertFreeCertificateContext(certContext)
	signer, err := openNCryptSigner(strings.TrimSpace(record.DeviceKeyName))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	cleanup := func() { signer.Close() }
	chain := [][]byte{cert.Raw}
	if strings.TrimSpace(record.DeviceCertificateChainPEM) != "" {
		for _, der := range certificateDERBlocks(record.DeviceCertificateChainPEM) {
			chain = append(chain, der)
		}
	}
	return tls.Certificate{Certificate: chain, PrivateKey: signer, Leaf: cert}, cleanup, nil
}

func certificateAllowsClientAuth(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

func certificateDERBlocks(rawPEM string) [][]byte {
	remaining := []byte(strings.TrimSpace(rawPEM))
	var blocks [][]byte
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, block.Bytes)
		}
		remaining = rest
	}
	return blocks
}

type ncryptSigner struct {
	handle       windows.Handle
	keyName      string
	providerName string
	publicKey    *rsa.PublicKey
}

func ensureNCryptSigner(keyName string) (*ncryptSigner, error) {
	if signer, err := openNCryptSigner(keyName); err == nil {
		return signer, nil
	}
	var lastErr error
	for _, providerName := range []string{msPlatformCryptoProvider, msSoftwareKSPProvider} {
		provider, err := ncryptOpenStorageProvider(providerName)
		if err != nil {
			lastErr = err
			continue
		}
		key, err := ncryptCreatePersistedRSAKey(provider, keyName)
		ncryptFreeObject(provider)
		if err != nil {
			lastErr = err
			continue
		}
		publicKey, err := ncryptRSAPublicKey(key)
		if err != nil {
			ncryptFreeObject(key)
			return nil, err
		}
		return &ncryptSigner{handle: key, keyName: keyName, providerName: providerName, publicKey: publicKey}, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("create persisted device key %q: no supported key storage provider", keyName)
}

func openNCryptSigner(keyName string) (*ncryptSigner, error) {
	for _, providerName := range []string{msPlatformCryptoProvider, msSoftwareKSPProvider} {
		provider, err := ncryptOpenStorageProvider(providerName)
		if err != nil {
			continue
		}
		key, err := ncryptOpenKey(provider, keyName)
		ncryptFreeObject(provider)
		if err != nil {
			continue
		}
		publicKey, err := ncryptRSAPublicKey(key)
		if err != nil {
			ncryptFreeObject(key)
			return nil, err
		}
		return &ncryptSigner{handle: key, keyName: keyName, providerName: providerName, publicKey: publicKey}, nil
	}
	return nil, fmt.Errorf("open persisted device key %q: key not found", keyName)
}

func (signer *ncryptSigner) Public() crypto.PublicKey {
	return signer.publicKey
}

func (signer *ncryptSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("NCrypt signer only supports SHA-256")
	}
	algID, err := windows.UTF16PtrFromString("SHA256")
	if err != nil {
		return nil, err
	}
	paddingInfo := bcryptPKCS1PaddingInfo{AlgID: algID}
	return ncryptSignHash(signer.handle, &paddingInfo, digest)
}

func (signer *ncryptSigner) Close() {
	if signer != nil && signer.handle != 0 {
		ncryptFreeObject(signer.handle)
		signer.handle = 0
	}
}

type bcryptPKCS1PaddingInfo struct {
	AlgID *uint16
}

func ncryptOpenStorageProvider(providerName string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(providerName)
	if err != nil {
		return 0, err
	}
	var provider windows.Handle
	status, _, _ := procNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&provider)), uintptr(unsafe.Pointer(name)), 0)
	if status != 0 {
		return 0, syscall.Errno(status)
	}
	return provider, nil
}

func ncryptOpenKey(provider windows.Handle, keyName string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(keyName)
	if err != nil {
		return 0, err
	}
	var key windows.Handle
	status, _, _ := procNCryptOpenKey.Call(uintptr(provider), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(name)), 0, ncryptMachineKeyFlag|ncryptSilentFlag)
	if status != 0 {
		return 0, syscall.Errno(status)
	}
	return key, nil
}

func ncryptCreatePersistedRSAKey(provider windows.Handle, keyName string) (windows.Handle, error) {
	algID, err := windows.UTF16PtrFromString(ncryptRSAAlgorithm)
	if err != nil {
		return 0, err
	}
	name, err := windows.UTF16PtrFromString(keyName)
	if err != nil {
		return 0, err
	}
	var key windows.Handle
	status, _, _ := procNCryptCreatePersistedKey.Call(uintptr(provider), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(algID)), uintptr(unsafe.Pointer(name)), 0, ncryptMachineKeyFlag|ncryptSilentFlag)
	if status != 0 {
		return 0, syscall.Errno(status)
	}
	length := uint32(2048)
	if err := ncryptSetPropertyDWORD(key, ncryptLengthProperty, length); err != nil {
		ncryptFreeObject(key)
		return 0, err
	}
	exportPolicy := uint32(0)
	if err := ncryptSetPropertyDWORD(key, ncryptExportPolicy, exportPolicy); err != nil {
		ncryptFreeObject(key)
		return 0, err
	}
	status, _, _ = procNCryptFinalizeKey.Call(uintptr(key), ncryptSilentFlag)
	if status != 0 {
		ncryptFreeObject(key)
		return 0, syscall.Errno(status)
	}
	return key, nil
}

func ncryptSetPropertyDWORD(key windows.Handle, property string, value uint32) error {
	propertyName, err := windows.UTF16PtrFromString(property)
	if err != nil {
		return err
	}
	status, _, _ := procNCryptSetProperty.Call(uintptr(key), uintptr(unsafe.Pointer(propertyName)), uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value), 0)
	if status != 0 {
		return syscall.Errno(status)
	}
	return nil
}

func ncryptRSAPublicKey(key windows.Handle) (*rsa.PublicKey, error) {
	blobType, err := windows.UTF16PtrFromString(bcryptRSAPublicBlob)
	if err != nil {
		return nil, err
	}
	var size uint32
	status, _, _ := procNCryptExportKey.Call(uintptr(key), 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if status != 0 {
		return nil, syscall.Errno(status)
	}
	blob := make([]byte, size)
	status, _, _ = procNCryptExportKey.Call(uintptr(key), 0, uintptr(unsafe.Pointer(blobType)), 0, uintptr(unsafe.Pointer(&blob[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), 0)
	if status != 0 {
		return nil, syscall.Errno(status)
	}
	return parseRSAPublicBlob(blob)
}

func parseRSAPublicBlob(blob []byte) (*rsa.PublicKey, error) {
	if len(blob) < 24 {
		return nil, fmt.Errorf("RSA public blob is too small")
	}
	expLen := int(binary.LittleEndian.Uint32(blob[8:12]))
	modLen := int(binary.LittleEndian.Uint32(blob[12:16]))
	offset := 24
	if len(blob) < offset+expLen+modLen {
		return nil, fmt.Errorf("RSA public blob is truncated")
	}
	expBytes := blob[offset : offset+expLen]
	offset += expLen
	modBytes := blob[offset : offset+modLen]
	exponent := 0
	for _, b := range expBytes {
		exponent = exponent<<8 + int(b)
	}
	if exponent == 0 {
		return nil, fmt.Errorf("RSA public exponent is empty")
	}
	modulus := new(big.Int).SetBytes(modBytes)
	if modulus.Sign() == 0 {
		return nil, fmt.Errorf("RSA public modulus is empty")
	}
	return &rsa.PublicKey{N: modulus, E: exponent}, nil
}

func ncryptSignHash(key windows.Handle, paddingInfo *bcryptPKCS1PaddingInfo, digest []byte) ([]byte, error) {
	var size uint32
	status, _, _ := procNCryptSignHash.Call(uintptr(key), uintptr(unsafe.Pointer(paddingInfo)), uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), 0, 0, uintptr(unsafe.Pointer(&size)), bcryptPadPKCS1)
	if status != 0 {
		return nil, syscall.Errno(status)
	}
	signature := make([]byte, size)
	status, _, _ = procNCryptSignHash.Call(uintptr(key), uintptr(unsafe.Pointer(paddingInfo)), uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), uintptr(unsafe.Pointer(&signature[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), bcryptPadPKCS1)
	if status != 0 {
		return nil, syscall.Errno(status)
	}
	return signature[:size], nil
}

func ncryptFreeObject(handle windows.Handle) {
	if handle != 0 {
		procNCryptFreeObject.Call(uintptr(handle))
	}
}

type cryptKeyProvInfo struct {
	ContainerName *uint16
	ProvName      *uint16
	ProvType      uint32
	Flags         uint32
	ProvParamC    uint32
	ProvParam     uintptr
	KeySpec       uint32
}

func setCertificateKeyProviderInfo(certContext *windows.CertContext, keyName, providerName string) error {
	container, err := windows.UTF16PtrFromString(strings.TrimSpace(keyName))
	if err != nil {
		return err
	}
	provider, err := windows.UTF16PtrFromString(strings.TrimSpace(providerName))
	if err != nil {
		return err
	}
	info := cryptKeyProvInfo{
		ContainerName: container,
		ProvName:      provider,
		Flags:         cryptMachineKeyset,
		KeySpec:       windows.CERT_NCRYPT_KEY_SPEC,
	}
	ok, _, callErr := procCertSetContextProperty.Call(uintptr(unsafe.Pointer(certContext)), certKeyProvInfoPropID, 0, uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		return fmt.Errorf("set certificate private key provider info: %w", callErr)
	}
	return nil
}

func openLocalMachineMyStore() (windows.Handle, error) {
	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return 0, err
	}
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_OPEN_EXISTING_FLAG, uintptr(unsafe.Pointer(storeName)))
	if err != nil {
		return 0, fmt.Errorf("open LocalMachine\\My certificate store: %w", err)
	}
	return store, nil
}

func findCertificateByThumbprint(thumbprint string) (*x509.Certificate, *windows.CertContext, error) {
	expected := strings.ToLower(strings.TrimSpace(thumbprint))
	if expected == "" {
		return nil, nil, nil
	}
	store, err := openLocalMachineMyStore()
	if err != nil {
		return nil, nil, err
	}
	defer windows.CertCloseStore(store, 0)
	var previous *windows.CertContext
	for {
		current, err := windows.CertEnumCertificatesInStore(store, previous)
		if current == nil {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.Errno(uintptr(windows.CRYPT_E_NOT_FOUND)) {
				return nil, nil, nil
			}
			return nil, nil, err
		}
		certBytes := unsafe.Slice(current.EncodedCert, current.Length)
		if strings.EqualFold(sha256Hex(certBytes), expected) {
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				_ = windows.CertFreeCertificateContext(current)
				return nil, nil, err
			}
			return cert, current, nil
		}
		previous = current
	}
}

func acquireCertificatePrivateKey(certContext *windows.CertContext) error {
	var key windows.Handle
	var keySpec uint32
	var callerFree bool
	err := windows.CryptAcquireCertificatePrivateKey(certContext, windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, nil, &key, &keySpec, &callerFree)
	if err != nil {
		return err
	}
	if callerFree && key != 0 {
		ncryptFreeObject(key)
	}
	return nil
}
