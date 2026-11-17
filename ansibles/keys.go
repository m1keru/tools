package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// newX25519 returns a key pair in the encoding Xray expects for REALITY and
// VLESS Encryption: 32 raw bytes, base64 RawURLEncoding. The private key is
// clamped the same way `xray x25519` does, so `xray x25519 -i <priv>` prints
// the same public key.
func newX25519() (priv, pub string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	return x25519FromBytes(b)
}

func x25519FromBytes(b []byte) (priv, pub string, err error) {
	if len(b) != 32 {
		return "", "", fmt.Errorf("x25519 private key must be 32 bytes, got %d", len(b))
	}
	k := make([]byte, 32)
	copy(k, b)
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	key, err := ecdh.X25519().NewPrivateKey(k)
	if err != nil {
		return "", "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(k), enc.EncodeToString(key.PublicKey().Bytes()), nil
}

// newUUID returns a random RFC 4122 version 4 UUID.
func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// randHex returns n random bytes, hex encoded.
func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// randToken returns n random bytes in URL-safe base64 without padding.
func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// newSelfSignedCert makes the certificate Hysteria2 presents inside QUIC. The
// handshake is wrapped in Salamander, so the certificate is never visible on
// the wire; clients authenticate the server by pinning its SHA-256.
func newSelfSignedCert(name string) (certPEM, keyPEM, sha256Hex string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return "", "", "", err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", "", err
	}
	sum := sha256.Sum256(der)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, hex.EncodeToString(sum[:]), nil
}
