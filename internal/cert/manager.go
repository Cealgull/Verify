package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/Cealgull/Verify/internal/proto"
)

type CertManager struct {
	priv       ed25519.PrivateKey
	cert       *x509.Certificate
	version    byte
	expiration time.Duration
}

const (
	CERT    = "CERTIFICATE"
	CSR     = "CERTIFICATE REQUEST"
	PRIVATE = "PRIVATE KEY"
)

type Option func(mgr *CertManager) error

func loadPem(data []byte, ftype string) ([]byte, error) {

	p, _ := pem.Decode(data)

	if p == nil {
		return nil, &FileDecodeError{}
	}

	if p.Type != ftype {
		return nil, &FileFormatError{}
	}

	return p.Bytes, nil
}

func loadPemFromDisk(file string, ftype string) ([]byte, error) {

	f, err := os.Open(file)

	if err != nil {
		return nil, &FileInternalError{}
	}

	b, _ := io.ReadAll(f)

	return loadPem(b, ftype)
}

func generatePem(ftype string, data []byte) []byte {
	p := &pem.Block{
		Type:  ftype,
		Bytes: data,
	}
	return pem.EncodeToMemory(p)
}

func WithPrivateKey(file string) Option {
	return func(mgr *CertManager) error {
		b, err := loadPemFromDisk(file, PRIVATE)

		if err != nil {
			return err
		}

		priv, err := x509.ParsePKCS8PrivateKey(b)

		if err != nil {
			return err
		}

		mgr.priv = priv.(ed25519.PrivateKey)
		return nil

	}
}

func WithCertificate(file string) Option {
	return func(mgr *CertManager) error {
		b, err := loadPemFromDisk(file, CERT)
		if err != nil {
			return err
		}

		cert, err := x509.ParseCertificate(b)

		if err != nil {
			return err
		}

		mgr.cert = cert

		return nil
	}
}

func WithVersion(ver byte) Option {
	return func(mgr *CertManager) error {
		mgr.version = ver
		return nil
	}
}

func WithExpiration(t int64) Option {
	return func(mgr *CertManager) error {
		mgr.expiration = time.Duration(t)
		return nil
	}
}

func NewCertManager(options ...Option) (*CertManager, error) {

	mgr := &CertManager{
		expiration: time.Duration(10),
		version:    0x01,
	}

	for _, option := range options {
		err := option(mgr)
		if err != nil {
			return nil, err
		}
	}
	return mgr, nil
}

func (m *CertManager) pubToAddress(pub []byte) string {

	magicbytes := []byte{m.version}
	payload := append(magicbytes, pub...)
	checksum := sha256.New().Sum(payload)
	checksum = sha256.New().Sum(checksum)[:4]

	payload = append(payload, checksum...)

	addr := hex.EncodeToString(payload)

	return string(addr)

}

func (m *CertManager) SignCSR(s string) ([]byte, proto.VerifyError) {

	b, err := base64.StdEncoding.DecodeString(s)

	if err != nil {
		return nil, &PubDecodeError{}
	}

	if len(b) != 32 {
		return nil, &PubFormatError{}
	}

	var pub ed25519.PublicKey = b

	sn := new(big.Int)
	sn = sn.Lsh(big.NewInt(1), 512)
	sn, _ = rand.Int(rand.Reader, sn)

	address := m.pubToAddress(b)

	cert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:         "0x" + address,
			Organization:       []string{"Cealgull"},
			OrganizationalUnit: []string{"Cealgull Project"},
		},
		Issuer:    m.cert.Subject,
		NotBefore: time.Now(),
	}

	b, err = x509.CreateCertificate(rand.Reader, cert, m.cert, pub, m.priv)

	if err != nil {
		return nil, &CertInternalError{}
	}

	return generatePem(CERT, b), nil
}

func (m *CertManager) VerifyCert(data []byte) (bool, proto.VerifyError) {

	b, err := loadPem(data, CERT)

	if _, ok := err.(*FileFormatError); ok {
		return false, &CertFormatError{}
	} else if _, ok := err.(*FileDecodeError); ok {
		return false, &CertDecodeError{}
	}

	cert, err := x509.ParseCertificate(b)

	if err != nil {
		return false, &CertFormatError{}
	}

	if err := cert.CheckSignatureFrom(m.cert); err != nil {
		return false, &CertUnauthorizedError{}
	}

	return true, nil

}
