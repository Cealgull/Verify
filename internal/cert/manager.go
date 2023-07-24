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

	"github.com/Cealgull/Verify/internal/cache"
	"github.com/Cealgull/Verify/internal/proto"
	"go.uber.org/zap"
)

type CertManager struct {
	logger     *zap.SugaredLogger
	priv       ed25519.PrivateKey
	cert       *x509.Certificate
	cache      cache.Cache
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

func WithCache(c cache.Cache) Option {
	return func(mgr *CertManager) error {
		mgr.cache = c
		return nil
	}
}

func NewCertManager(logger *zap.SugaredLogger, options ...Option) (*CertManager, error) {

	mgr := &CertManager{
		logger:     logger,
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

const codeSet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func (m *CertManager) Base58EncodeString(data []byte) string {
	x := big.NewInt(0).SetBytes(data)
	y := big.NewInt(58)
	zero := big.NewInt(0)
	r := big.NewInt(0)
	result := ""
	for x.Cmp(zero) != 0 {
		x, r = x.QuoRem(x, y, r)
		result += string(codeSet[r.Int64()])
	}
	return result
}

func (m *CertManager) pubToAddress(pub []byte) string {

	magicbytes := []byte{m.version}
	payload := append(magicbytes, pub...)
	checksum := sha256.New().Sum(payload)
	checksum = sha256.New().Sum(checksum)[:4]

	payload = append(payload, checksum...)

	addr := m.Base58EncodeString(payload)

	return string(addr)

}

func (m *CertManager) createCertificate(s string) ([]byte, proto.VerifyError) {

	var pub ed25519.PublicKey

	pub, err := base64.StdEncoding.DecodeString(s)

	if err != nil {
		m.logger.Debugf("Base64 decoding error for public key: %s.", s)
		return nil, &PubDecodeError{}
	}

	if len(pub) != 32 {
		m.logger.Debugf("Invalid ed25519 public key size: %s.", s)
		return nil, &PubFormatError{}
	}

	sn := new(big.Int)
	sn = sn.Lsh(big.NewInt(1), 512)
	sn, _ = rand.Int(rand.Reader, sn)

	address := m.pubToAddress(pub)
	m.logger.Infof("Signing certificate for public andress: 0x%s.", address)

	template := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:         "0x" + address,
			Organization:       []string{"Cealgull"},
			OrganizationalUnit: []string{"Cealgull Project"},
		},
		Issuer:    m.cert.Subject,
		NotBefore: time.Now(),
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, m.cert, pub, m.priv)

	if err != nil {
		m.logger.Debugf("Error when creating certificates. err: %s", err.Error())
		return nil, &CertInternalError{}
	}

	m.logger.Infof("Signing Completed for address: 0x%s.", address)

	return generatePem(CERT, cert), nil
}

func (m *CertManager) SignCSR(s string) ([]byte, proto.VerifyError) {

	m.logger.Infof("Signing Certificate for public key: %s.", s)

	cert, err := m.createCertificate(s)

	if err != nil {
		return nil, err
	}

	if err := m.cache.SAdd("pub", s); err != nil {
		m.logger.Errorf("Redis failure happened when signing %s. err: %s.", err.Error())
		return nil, &CertInternalError{}
	}

	return cert, nil
}

func (m *CertManager) ResignCSR(s string) ([]byte, proto.VerifyError) {

	valid, err := m.cache.SIsmember("pub", s)

	if err != nil {
		m.logger.Errorf("Redis failure happened when checking existence. err: %s.", err.Error())
		return nil, &CertInternalError{}
	}

	if !valid {
		m.logger.Debugf("Public Key: %s missing when resigning", s)
		return nil, &PubNotFoundError{}
	}

	m.logger.Infof("Resigning Certificate for public key: %s.", s)

	return m.createCertificate(s)

}

func (m *CertManager) VerifyCert(data []byte) (bool, proto.VerifyError) {

	b, err := loadPem(data, CERT)

	m.logger.Info("Responding to new certificate verification request.")

	if _, ok := err.(*FileFormatError); ok {
		m.logger.Debug("Wrong certficate pem format when verifying.")
		return false, &CertFormatError{}
	} else if _, ok := err.(*FileDecodeError); ok {
		m.logger.Debug("Error when decoding certificate pem body.")
		return false, &CertDecodeError{}
	}

	cert, err := x509.ParseCertificate(b)

	if err != nil {
		m.logger.Debug("Error when loading certificate.")
		return false, &CertFormatError{}
	}

	if err := cert.CheckSignatureFrom(m.cert); err != nil {
		m.logger.Debug("Certificate is not signed by the current host.")
		return false, &CertUnauthorizedError{}
	}

	m.logger.Info("Certificate verification success.")

	return true, nil

}
