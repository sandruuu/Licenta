//go:build windows

package deviceidentity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ncryptECDSAP256Algorithm         = "ECDSA_P256"
	bcryptECCPublicBlob              = "ECCPUBLICBLOB"
	ncryptKeyUsageProperty           = "Key Usage"
	ncryptAllowSigningFlag           = 0x00000002
	nteExists                uintptr = 0x8009000f
)

var (
	procNCryptCreatePersistedKey = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptSetProperty        = ncrypt.NewProc("NCryptSetProperty")
	procNCryptFinalizeKey        = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptExportKey          = ncrypt.NewProc("NCryptExportKey")
	procNCryptSignHash           = ncrypt.NewProc("NCryptSignHash")
)

type ncryptSigner struct {
	key    ncryptHandle
	public *ecdsa.PublicKey
}

type ecdsaASN1Signature struct {
	R, S *big.Int
}

func (*KeyStore) EnsureSigningKey(ctx context.Context, keyName string) (crypto.Signer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	keyName = strings.TrimSpace(keyName)
	if keyName == "" {
		return nil, fmt.Errorf("key name is required")
	}
	provider, err := openStorageProvider(MicrosoftPlatformCryptoProvider)
	if err != nil {
		return nil, err
	}
	defer freeObject(provider)
	key, err := openMachineKey(provider, keyName)
	if err != nil {
		if !isNCryptStatus(err, nteBadKeyset, nteNotFound) {
			return nil, err
		}
		key, err = createMachineSigningKey(provider, keyName)
		if err != nil {
			if isNCryptStatus(err, nteExists) {
				key, err = openMachineKey(provider, keyName)
			}
			if err != nil {
				return nil, err
			}
		}
	}
	return signerFromNCryptKey(key)
}

func (*KeyStore) OpenSigningKey(ctx context.Context, keyName string) (crypto.Signer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	keyName = strings.TrimSpace(keyName)
	if keyName == "" {
		return nil, fmt.Errorf("key name is required")
	}
	provider, err := openStorageProvider(MicrosoftPlatformCryptoProvider)
	if err != nil {
		return nil, err
	}
	defer freeObject(provider)
	key, err := openMachineKey(provider, keyName)
	if err != nil {
		return nil, err
	}
	return signerFromNCryptKey(key)
}

func signerFromNCryptKey(key ncryptHandle) (crypto.Signer, error) {
	publicKey, err := exportECDSAPublicKey(key)
	if err != nil {
		freeObject(key)
		return nil, err
	}
	signer := &ncryptSigner{key: key, public: publicKey}
	runtime.SetFinalizer(signer, func(signer *ncryptSigner) { freeObject(signer.key) })
	return signer, nil
}

func createMachineSigningKey(provider ncryptHandle, keyName string) (ncryptHandle, error) {
	algorithm, err := windows.UTF16PtrFromString(ncryptECDSAP256Algorithm)
	if err != nil {
		return 0, err
	}
	name, err := windows.UTF16PtrFromString(keyName)
	if err != nil {
		return 0, err
	}
	var key uintptr
	status, _, _ := procNCryptCreatePersistedKey.Call(
		uintptr(provider),
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(algorithm)),
		uintptr(unsafe.Pointer(name)),
		0,
		ncryptMachineKeyFlag,
	)
	if status != 0 {
		return 0, ncryptStatus(status)
	}
	handle := ncryptHandle(key)
	usage := uint32(ncryptAllowSigningFlag)
	if err := setNCryptPropertyBytes(handle, ncryptKeyUsageProperty, unsafe.Slice((*byte)(unsafe.Pointer(&usage)), unsafe.Sizeof(usage)), 0); err != nil {
		freeObject(handle)
		return 0, err
	}
	status, _, _ = procNCryptFinalizeKey.Call(uintptr(handle), ncryptSilentFlag)
	if status != 0 {
		freeObject(handle)
		return 0, ncryptStatus(status)
	}
	return handle, nil
}

func (signer *ncryptSigner) Public() crypto.PublicKey {
	if signer == nil {
		return nil
	}
	return signer.public
}

func (signer *ncryptSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if signer == nil || signer.key == 0 {
		return nil, fmt.Errorf("NCrypt signer is unavailable")
	}
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, fmt.Errorf("NCrypt signer requires a SHA-256 digest")
	}
	signature, err := signHash(signer.key, digest)
	if err != nil {
		return nil, err
	}
	if len(signature)%2 != 0 || len(signature) == 0 {
		return nil, fmt.Errorf("unexpected ECDSA signature size %d", len(signature))
	}
	half := len(signature) / 2
	r := new(big.Int).SetBytes(signature[:half])
	s := new(big.Int).SetBytes(signature[half:])
	return asn1.Marshal(ecdsaASN1Signature{R: r, S: s})
}

func signHash(key ncryptHandle, digest []byte) ([]byte, error) {
	var size uint32
	status, _, _ := procNCryptSignHash.Call(
		uintptr(key),
		0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(uint32(len(digest))),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if status != 0 {
		return nil, ncryptStatus(status)
	}
	if size == 0 {
		return nil, errors.New("NCrypt signature is empty")
	}
	buf := make([]byte, size)
	status, _, _ = procNCryptSignHash.Call(
		uintptr(key),
		0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(uint32(len(digest))),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if status != 0 {
		return nil, ncryptStatus(status)
	}
	return buf[:size], nil
}

func exportECDSAPublicKey(key ncryptHandle) (*ecdsa.PublicKey, error) {
	blobType, err := windows.UTF16PtrFromString(bcryptECCPublicBlob)
	if err != nil {
		return nil, err
	}
	var size uint32
	status, _, _ := procNCryptExportKey.Call(
		uintptr(key),
		0,
		uintptr(unsafe.Pointer(blobType)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if status != 0 {
		return nil, ncryptStatus(status)
	}
	if size < 8 {
		return nil, fmt.Errorf("NCrypt public key blob is too small")
	}
	buf := make([]byte, size)
	status, _, _ = procNCryptExportKey.Call(
		uintptr(key),
		0,
		uintptr(unsafe.Pointer(blobType)),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if status != 0 {
		return nil, ncryptStatus(status)
	}
	buf = buf[:size]
	coordinateSize := int(binary.LittleEndian.Uint32(buf[4:8]))
	if coordinateSize <= 0 || len(buf) < 8+2*coordinateSize {
		return nil, fmt.Errorf("invalid NCrypt ECC public key blob")
	}
	x := new(big.Int).SetBytes(buf[8 : 8+coordinateSize])
	y := new(big.Int).SetBytes(buf[8+coordinateSize : 8+2*coordinateSize])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("NCrypt public key is not on P-256")
	}
	return pub, nil
}

func setNCryptPropertyBytes(handle ncryptHandle, property string, data []byte, flags uintptr) error {
	name, err := windows.UTF16PtrFromString(property)
	if err != nil {
		return err
	}
	var dataPtr uintptr
	if len(data) > 0 {
		dataPtr = uintptr(unsafe.Pointer(&data[0]))
	}
	status, _, _ := procNCryptSetProperty.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(name)),
		dataPtr,
		uintptr(uint32(len(data))),
		flags,
	)
	if status != 0 {
		return ncryptStatus(status)
	}
	return nil
}
