package tpmauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// tpmSigner implements crypto.Signer using a TPM2 key.
type tpmSigner struct {
	tpm    transport.TPMCloser
	handle tpm2.TPMHandle
	pub    *ecdsa.PublicKey
	name   tpm2.TPM2BName
}

// tpmKeyBlobs holds the serialized key material for loading into TPM.
type tpmKeyBlobs struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

func (s *tpmSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signCmd := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: s.handle,
			Name:   s.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA256,
			}),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}

	signResp, err := signCmd.Execute(s.tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM sign: %w", err)
	}

	eccsig, err := signResp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("parse ECDSA sig: %w", err)
	}

	r := new(big.Int).SetBytes(eccsig.SignatureR.Buffer)
	sVal := new(big.Int).SetBytes(eccsig.SignatureS.Buffer)

	return asn1EncodeECDSASig(r, sVal), nil
}

// asn1EncodeECDSASig encodes r,s into ASN.1 DER ECDSA signature format.
func asn1EncodeECDSASig(r, s *big.Int) []byte {
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	if len(rBytes) > 0 && rBytes[0]&0x80 != 0 {
		rBytes = append([]byte{0}, rBytes...)
	}
	if len(sBytes) > 0 && sBytes[0]&0x80 != 0 {
		sBytes = append([]byte{0}, sBytes...)
	}
	inner := make([]byte, 0, 6+len(rBytes)+len(sBytes))
	inner = append(inner, 0x02, byte(len(rBytes)))
	inner = append(inner, rBytes...)
	inner = append(inner, 0x02, byte(len(sBytes)))
	inner = append(inner, sBytes...)

	result := make([]byte, 0, 2+len(inner))
	result = append(result, 0x30, byte(len(inner)))
	result = append(result, inner...)
	return result
}

// loadOrCreateTPMKey tries to open the platform TPM and load (or create) a
// signing key under the Storage Root Key (SRK).
func loadOrCreateTPMKey(dataDir string) (crypto.Signer, error) {
	tpmDev, err := transport.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("open TPM: %w", err)
	}

	// Create SRK (ECC, not persistent — recreated each session)
	srkResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(tpmDev)
	if err != nil {
		tpmDev.Close()
		return nil, fmt.Errorf("create SRK: %w", err)
	}

	blobPath := filepath.Join(dataDir, "tpm-key.json")

	// Try to load existing key blobs from disk
	if blobData, err := os.ReadFile(blobPath); err == nil {
		var blobs tpmKeyBlobs
		if err := json.Unmarshal(blobData, &blobs); err == nil {
			loadResp, err := tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: srkResp.ObjectHandle,
					Name:   srkResp.Name,
					Auth:   tpm2.PasswordAuth(nil),
				},
				InPrivate: tpm2.TPM2BPrivate{Buffer: blobs.Private},
				InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](blobs.Public),
			}.Execute(tpmDev)
			if err == nil {
				pubKey, err := extractECCPub(tpmDev, loadResp.ObjectHandle)
				if err == nil {
					slog.Info("Loaded existing TPM key", "path", blobPath)
					return &tpmSigner{tpm: tpmDev, handle: loadResp.ObjectHandle, pub: pubKey, name: loadResp.Name}, nil
				}
			}
			slog.Warn("Failed to load TPM key blobs, creating new key", "error", err)
		}
	}

	// Create new signing key under SRK
	eccTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256,
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
		}),
	}

	createResp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkResp.ObjectHandle,
			Name:   srkResp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(eccTemplate),
	}.Execute(tpmDev)
	if err != nil {
		tpmDev.Close()
		return nil, fmt.Errorf("create TPM key: %w", err)
	}

	// Load the newly created key
	loadResp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkResp.ObjectHandle,
			Name:   srkResp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: createResp.OutPrivate,
		InPublic:  createResp.OutPublic,
	}.Execute(tpmDev)
	if err != nil {
		tpmDev.Close()
		return nil, fmt.Errorf("load TPM key: %w", err)
	}

	// Save blobs for future sessions
	pubBytes := tpm2.Marshal(createResp.OutPublic)
	blobs := tpmKeyBlobs{
		Public:  pubBytes,
		Private: createResp.OutPrivate.Buffer,
	}
	blobJSON, _ := json.Marshal(blobs)
	if err := os.WriteFile(blobPath, blobJSON, 0600); err != nil {
		slog.Warn("Failed to persist TPM key blobs", "error", err)
	}

	pubKey, err := extractECCPub(tpmDev, loadResp.ObjectHandle)
	if err != nil {
		tpmDev.Close()
		return nil, fmt.Errorf("extract public key: %w", err)
	}

	slog.Info("Created new TPM-backed ECDSA P-256 key", "path", blobPath)
	return &tpmSigner{tpm: tpmDev, handle: loadResp.ObjectHandle, pub: pubKey, name: loadResp.Name}, nil
}

// ReadEKPub reads the Endorsement Key public portion from the TPM.
// The EK is a stable, device-unique identity anchored in hardware.
// Returns the ECC public key or an error if the TPM/EK is unavailable.
func ReadEKPub() (*ecdsa.PublicKey, error) {
	tpmDev, err := transport.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("open TPM: %w", err)
	}
	defer tpmDev.Close()

	// Create the EK primary in the Endorsement hierarchy using the standard ECC template.
	// This is deterministic — same TPM always produces the same EK.
	ekResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("create EK primary: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: ekResp.ObjectHandle}.Execute(tpmDev)

	return extractECCPub(tpmDev, ekResp.ObjectHandle)
}

// extractECCPub reads the public point from a TPM ECC key.
func extractECCPub(tpmDev transport.TPMCloser, handle tpm2.TPMHandle) (*ecdsa.PublicKey, error) {
	readResp, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("read public: %w", err)
	}

	pub, err := readResp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("parse public: %w", err)
	}

	eccPub, err := pub.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("get ECC point: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(eccPub.X.Buffer),
		Y:     new(big.Int).SetBytes(eccPub.Y.Buffer),
	}, nil
}
