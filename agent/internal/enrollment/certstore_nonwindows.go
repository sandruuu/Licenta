//go:build !windows

package enrollment

func NewDefaultCertificateInstaller() CertificateInstaller {
	return NoopCertificateInstaller{}
}
