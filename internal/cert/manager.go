package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/Cealgull/Verify/internal/proto"
)

type CertManager struct {
	priv ed25519.PrivateKey
	cert *x509.Certificate
}

const (
	CERT    = "CERTIFICATE"
	CSR     = "CERTIFICATE REQUEST"
	PRIVATE = "PRIVATE KEY"
)

type Option func(mgr *CertManager) error

func loadPem(data []byte, ftype string) ([]byte, error) {

	p, _ := pem.Decode(data)

	if p == nil || p.Type != ftype {
		return nil, &InternalError{}
	}

	return p.Bytes, nil
}

func loadPemFromDisk(file string, ftype string) ([]byte, error) {

	f, err := os.Open(file)

	if err != nil {
		return nil, &InternalError{}
	}

	b, err := io.ReadAll(f)

	if err != nil {
		return nil, &InternalError{}
	}
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

func NewCertManager(options ...Option) (*CertManager, error) {
	mgr := new(CertManager)
	for _, option := range options {
		err := option(mgr)
		if err != nil {
			return nil, err
		}
	}
	return mgr, nil
}

func (m *CertManager) SignCSR(data []byte) ([]byte, proto.VerifyError) {

	b, err := loadPem(data, CSR)

	if err != nil {
		return nil, &InternalError{}
	}

	csr, err := x509.ParseCertificateRequest(b)

	if err != nil {
		return nil, &InternalError{}
	}

	sn := new(big.Int)
	sn = sn.Lsh(big.NewInt(1), 512)
	sn, _ = rand.Int(rand.Reader, sn)

	pk, _ := m.cert.PublicKey.([64]byte)

	cert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:   csr.Subject.CommonName,
			Organization: []string{"Cealgull"},
			SerialNumber: csr.Subject.SerialNumber,
		},
		SubjectKeyId:       sha512.New().Sum(pk[:]),
		Issuer:             m.cert.Subject,
		NotBefore:          time.Now(),
		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		SignatureAlgorithm: csr.SignatureAlgorithm,
	}

	b, err = x509.CreateCertificate(rand.Reader, cert, m.cert, cert.PublicKey, m.priv)

	if err != nil {
		return nil, &InternalError{}
	}

	return generatePem(CERT, b), nil
}

func (m *CertManager) VerifyCert(data []byte) (bool, proto.VerifyError) {

	b, err := loadPem(data, CERT)

	if err != nil {
		return false, &InternalError{}
	}

	cert, err := x509.ParseCertificate(b)

	if err != nil {
		return false, &BadRequestError{}
	}

	if err := cert.CheckSignatureFrom(m.cert); err != nil {
		return false, &UnauthorizedError{}
	}

	pool := x509.NewCertPool()
	pool.AddCert(m.cert)

	chain, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: time.Now(),
	})

	if err != nil || chain == nil {
		return false, &UnauthorizedError{}
	}

	return true, nil

}
