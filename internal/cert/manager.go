package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/Cealgull/Verify/internal/proto"
	base58 "github.com/itchyny/base58-go"
)

type CertManager struct {
	priv       ed25519.PrivateKey
	cert       *x509.Certificate
	magic      string
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

func WithMagic(magic string) Option {
	return func(mgr *CertManager) error {
		mgr.magic = magic
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
		magic:      "Cealgull",
	}

	for _, option := range options {
		err := option(mgr)
		if err != nil {
			return nil, err
		}
	}
	return mgr, nil
}

func pubToAddress(pub []byte, magic string) string {

	pubhash := sha256.New().Sum(pub)
	magicbytes := []byte(magic)
	magicbytes = append(magicbytes, pubhash...)
	checksum := sha256.New().Sum(magicbytes)[:4]
	pubhash = append(pubhash, checksum...)

	addr, _ := base58.BitcoinEncoding.Encode(pubhash)

	return string(addr)

}

func (m *CertManager) SignCSR(s string) ([]byte, proto.VerifyError) {

	b, err := base64.StdEncoding.DecodeString(s)

	if len(b) != 32 || err != nil {
		return nil, &BadRequestError{}
	}

	var pub ed25519.PublicKey = b

	sn := new(big.Int)
	sn = sn.Lsh(big.NewInt(1), 512)
	sn, _ = rand.Int(rand.Reader, sn)

	address := pubToAddress(b, m.magic)

	cert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName: address,
		},
		Issuer:    m.cert.Subject,
		NotBefore: time.Now(),
	}

	b, err = x509.CreateCertificate(rand.Reader, cert, m.cert, pub, m.priv)

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

	return true, nil

}
