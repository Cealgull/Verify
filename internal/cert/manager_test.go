package cert

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"testing"

	"github.com/Cealgull/Verify/internal/cache"
	"github.com/Cealgull/Verify/internal/cache/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

var mgr *CertManager
var c *mock.MockCache
var pubb64 string
var cert []byte

func TestLoadPem(t *testing.T) {

	b, err := loadPemFromDisk("./notexists", CERT)
	assert.Nil(t, b)
	assert.Error(t, err)
	var _ = err.Error()

	b, err = loadPemFromDisk("./testdata/pem_invalid.pem", CERT)
	assert.Nil(t, b)
	assert.Error(t, err)
	var _ = err.Error()

	b, err = loadPemFromDisk("./testdata/priv.pem", CERT)
	assert.Nil(t, b)
	assert.Error(t, err)
	var _ = err.Error()

	b, err = loadPemFromDisk("./testdata/priv.pem", PRIVATE)
	assert.NotNil(t, b)
	assert.NoError(t, err)
}

func TestNewCertManager(t *testing.T) {

	var err error
	c = mock.NewMockCache()

	l, _ := zap.NewProduction()
	logger := l.Sugar()

	mgr, err := NewCertManager(
		logger,
		WithVersion(0x02),
		WithExpiration(32),
		WithPrivateKey("./notexists"),
	)
	assert.Nil(t, mgr)
	assert.Error(t, err)

	mgr, err = NewCertManager(
		logger,
		WithCertificate("./notexists"),
	)
	assert.Nil(t, mgr)
	assert.Error(t, err)

	mgr, err = NewCertManager(
		logger,
		WithPrivateKey("./testdata/priv_invalid.pem"),
	)
	assert.Nil(t, mgr)
	assert.Error(t, err)

	mgr, err = NewCertManager(
		logger,
		WithCertificate("./testdata/cert_invalid.pem"),
	)
	assert.Nil(t, mgr)
	assert.Error(t, err)

}

func TestSignPublicKey(t *testing.T) {

	l, _ := zap.NewProduction()
	logger := l.Sugar()

	mgr, _ = NewCertManager(
		logger,
		WithPrivateKey("./testdata/priv.pem"),
		WithCertificate("./testdata/cert_unsigned.pem"),
		WithCache(c))

	pubb64 = "asbcd"
	_, err := mgr.SignCSR(pubb64)
	assert.NotNil(t, err)
	var _ = err.Status()
	var _ = err.Message()

	pubb64 = base64.StdEncoding.EncodeToString([]byte{0x01, 0x02})
	_, err = mgr.SignCSR(pubb64)
	assert.NotNil(t, err)
	var _ = err.Status()
	var _ = err.Message()

	pub, _, _ := ed25519.GenerateKey(nil)
	pubb64 = base64.StdEncoding.EncodeToString(pub)
	_, err = mgr.SignCSR(pubb64)
	assert.NotNil(t, err)
	var _ = err.Status()
	var _ = err.Message()

	mgr, _ = NewCertManager(
		logger,
		WithPrivateKey("./testdata/priv.pem"),
		WithCertificate("./testdata/cert.pem"),
		WithCache(c))

	c.AddSetsErr("pub", &cache.InternalError{})
	_, err = mgr.SignCSR(pubb64)
	assert.NotNil(t, err)
	var _ = err.Status()
	var _ = err.Message()
	c.DelSetsErr("pub")

	cert, err = mgr.SignCSR(pubb64)
	assert.NotNil(t, cert)
	assert.Nil(t, err)

}

func TestResignPublicKey(t *testing.T) {

	pubb64_invalid := "asfasfe"
	_, err := mgr.ResignCSR(pubb64_invalid)
	assert.NotNil(t, err)
	var _ = err.Status()
	var _ = err.Message()

	c.AddSetsErr("pub", &cache.InternalError{})
	_, err = mgr.ResignCSR(pubb64)
	assert.NotNil(t, err)
	var _ = err.Status()
	var _ = err.Message()
	c.DelSetsErr("pub")

	_, err = mgr.ResignCSR(pubb64)
	assert.Nil(t, err)
}

func TestVerifyCert(t *testing.T) {

	f, _ := os.Open("./testdata/pem_invalid.pem")
	b, _ := io.ReadAll(f)
	_, err := mgr.VerifyCert(b)
	assert.NotNil(t, err)
	var _ = err.Status()
	var _ = err.Message()

	f, _ = os.Open("./testdata/priv.pem")
	b, _ = io.ReadAll(f)
	_, err = mgr.VerifyCert(b)
	assert.NotNil(t, err)
	var _ = err.Status()
	var _ = err.Message()

	f, _ = os.Open("./testdata/cert_invalid.pem")
	b, _ = io.ReadAll(f)
	_, err = mgr.VerifyCert(b)
	assert.NotNil(t, err)
	var _ = err.Status()
	var _ = err.Message()

	f, _ = os.Open("./testdata/cert_unsigned.pem")
	b, _ = io.ReadAll(f)
	_, err = mgr.VerifyCert(b)
	assert.NotNil(t, err)
	var _ = err.Status()
	var _ = err.Message()

	ok, err := mgr.VerifyCert(cert)
	assert.Nil(t, err)
	assert.True(t, ok)
}
