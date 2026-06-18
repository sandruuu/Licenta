package dataplane

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"

	gatewaycert "gateway/internal/cert"
	"gateway/internal/config"
)

func (gateway *Gateway) listen() (net.Listener, error) {
	tlsConfig, useTLS, err := gateway.buildServerTLSConfig()
	if err != nil {
		return nil, err
	}
	baseListener, err := net.Listen("tcp", agentListenAddr)
	if err != nil {
		return nil, err
	}
	if !useTLS {
		baseListener.Close()
		return nil, fmt.Errorf("gateway certificate and key are required")
	}
	return tls.NewListener(baseListener, tlsConfig), nil
}

func (gateway *Gateway) buildServerTLSConfig() (*tls.Config, bool, error) {
	clientCAPool, err := gateway.clientCAPool()
	if err != nil {
		return nil, false, err
	}
	if clientCAPool == nil {
		return nil, false, fmt.Errorf("Agent mTLS requires PA CA or a reachable PA CA endpoint")
	}
	if _, err := loadGatewayServerCertificate(); err != nil {
		return nil, false, err
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientCAs:  clientCAPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := loadGatewayServerCertificate()
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("client certificate is required")
			}
			cert := state.PeerCertificates[0]
			for _, key := range serialLookupKeys(cert.SerialNumber) {
				if _, revoked := gateway.revokedSerials.Load(key); revoked {
					return fmt.Errorf("client certificate serial %s is revoked", cert.SerialNumber.String())
				}
			}
			return nil
		},
	}

	return tlsConfig, true, nil
}

func loadGatewayServerCertificate() (tls.Certificate, error) {
	cert, err := gatewaycert.LoadGatewayKeyPairAndValidateCert(config.GatewayCertPath, config.GatewayKeyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load gateway TLS key pair: %w", err)
	}
	return cert, nil
}

func (gateway *Gateway) clientCAPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	added := false
	for _, path := range []string{config.PACAPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read client CA %s: %w", path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("parse client CA %s", path)
		}
		added = true
	}
	if gateway.controlPlane != nil {
		if caPEM, err := gateway.controlPlane.GetCACert(); err == nil && len(caPEM) > 0 {
			if pool.AppendCertsFromPEM(caPEM) {
				added = true
			}
		} else {
			log.Printf("[GATEWAY] PA CA fetch failed: %v", err)
		}
	}
	if !added {
		return nil, nil
	}
	return pool, nil
}
