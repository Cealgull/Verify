package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Cealgull/Verify/internal/cache"
	mockcache "github.com/Cealgull/Verify/internal/cache/mock"
	"github.com/Cealgull/Verify/internal/cert"
	"github.com/Cealgull/Verify/internal/email"
	"github.com/Cealgull/Verify/internal/keyset"
	"github.com/Cealgull/Verify/pkg/keypair"
	"github.com/Cealgull/Verify/pkg/turnstile"
	"github.com/labstack/echo/v4"
	mocksmtp "github.com/mocktools/go-smtp-mock/v2"
	"github.com/stretchr/testify/assert"
	edsuite "go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/anon"
)

var smtpServer *mocksmtp.Server
var mc *mockcache.MockCache
var verify *VerificationServer
var dialer *email.EmailDialer
var kp keypair.KeyPair
var errjson = "114514"
var code string
var cacert CACert

func TestNewVerificationServer(t *testing.T) {

	smtpServer = mocksmtp.New(mocksmtp.ConfigurationAttr{
		PortNumber:              2000,
		LogToStdout:             false,
		LogServerActivity:       false,
		BlacklistedRcpttoEmails: []string{"user3@example2.org"},
	})

	err := smtpServer.Start()
	assert.Nil(t, err)

	dialer, err = email.NewEmailDialer(
		email.WithClient("localhost", 2000, "user1@example1.org", "secret"),
		email.WithToDom("example2.org"),
		email.WithSubject("Testing"),
	)

	assert.NoError(t, err)

	mc = mockcache.NewMockCache()

	em, err := email.NewEmailManager(
		email.WithEmailDialer(dialer),
		email.WithCache(mc),
		email.WithAccExp("^[a-zA-Z0-9-_\\.]{3,50}$"),
		email.WithEmailTemplate("this is a testing code %06d"),
		email.WithCodeExp("^[0-9]{6}$"),
	)
	assert.Nil(t, err)

	km, err := keyset.NewKeyManager(16, 16)
	assert.NoError(t, err)

	ts := turnstile.NewTurnstile("secret")

	cm, err := cert.NewCertManager(
		cert.WithCertificate("./testdata/cert.pem"),
		cert.WithPrivateKey("./testdata/priv.pem"),
		cert.WithCache(mc),
	)

	assert.NoError(t, err)

	verify = NewVerificationServer("0.0.0.1", 20000, em, cm, km, ts)

}

func TestSignHandler(t *testing.T) {

	req := httptest.NewRequest(http.MethodPost, "/email/sign", strings.NewReader(errjson))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := verify.ec.NewContext(req, rec)

	assert.NoError(t, verify.emailSign(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	signRequest := EmailRequest{
		Account: "@!#@",
		Code:    "",
	}

	data, _ := json.Marshal(&signRequest)

	req = httptest.NewRequest(http.MethodPost, "/email/sign", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.emailSign(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	signRequest = EmailRequest{
		Account: "user1",
		Code:    "",
	}

	data, _ = json.Marshal(&signRequest)

	req = httptest.NewRequest(http.MethodPost, "/email/sign", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.emailSign(c))

	var err error
	code, err = mc.Get("user1")
	assert.NoError(t, err)
}

func TestVerifyHandler(t *testing.T) {

	req := httptest.NewRequest(http.MethodPost, "/email/verify", strings.NewReader(errjson))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.emailVerify(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	signRequest := EmailRequest{
		Account: "@!##$",
	}

	data, _ := json.Marshal(&signRequest)

	req = httptest.NewRequest(http.MethodPost, "/email/verify", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.emailVerify(c))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var wrongCode string

	for {
		wrongCode = fmt.Sprintf("%06d", rand.Intn(100000))
		if wrongCode != code {
			break
		}
	}

	signRequest = EmailRequest{
		Account: "user1",
		Code:    wrongCode,
	}

	data, _ = json.Marshal(&signRequest)

	req = httptest.NewRequest(http.MethodPost, "/email/verify", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.emailVerify(c))

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	signRequest = EmailRequest{
		Account: "user1",
		Code:    code,
	}

	data, _ = json.Marshal(&signRequest)

	req = httptest.NewRequest(http.MethodPost, "/email/verify", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.emailVerify(c))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &kp))
}

var pubb64 string

func TestCertSign(t *testing.T) {

	pub, _, _ := ed25519.GenerateKey(nil)
	pubb64 = base64.StdEncoding.EncodeToString(pub)
	certreq := CertRequest{pubb64}
	data, _ := json.Marshal(&certreq)

	suite := edsuite.NewBlakeSHA256Ed25519()
	sig := anon.Sign(suite, []byte(pubb64), kp.Pubs, nil, kp.Idx, kp.Priv)
	sigb64 := base64.StdEncoding.EncodeToString(sig)

	// test header missing
	req := httptest.NewRequest(http.MethodPost, "/cert/sign", bytes.NewReader(data))
	rec := httptest.NewRecorder()
	c := verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.certSign(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// test signature missing
	req = httptest.NewRequest(http.MethodPost, "/cert/sign", bytes.NewReader(data))
	rec = httptest.NewRecorder()
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.certSign(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// test signature bad request
	req = httptest.NewRequest(http.MethodPost, "/cert/sign", bytes.NewReader(data))
	rec = httptest.NewRecorder()
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("signature", "&^(*&")
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.certSign(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// test cert signing failure
	req = httptest.NewRequest(http.MethodPost, "/cert/sign", bytes.NewReader(data))
	rec = httptest.NewRecorder()
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("signature", sigb64)
	mc.AddSetsErr("pub", &cache.InternalError{})
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.certSign(c))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	mc.DelSetsErr("pub")

	req = httptest.NewRequest(http.MethodPost, "/cert/sign", bytes.NewReader(data))
	rec = httptest.NewRecorder()
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("signature", sigb64)
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.certSign(c))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &cacert))

}

func TestCertResign(t *testing.T) {

	pubnew, _, _ := ed25519.GenerateKey(nil)
	pubnewb64 := base64.StdEncoding.EncodeToString(pubnew)
	certreq := CertRequest{pubnewb64}
	data, _ := json.Marshal(&certreq)

	// test header missing
	req := httptest.NewRequest(http.MethodPost, "/cert/resign", bytes.NewReader(data))
	rec := httptest.NewRecorder()
	c := verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.certResign(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// test not enrolled public key
	req = httptest.NewRequest(http.MethodPost, "/cert/resign", bytes.NewReader(data))
	rec = httptest.NewRecorder()
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.certResign(c))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// test OK
	data, _ = json.Marshal(&CertRequest{pubb64})
	req = httptest.NewRequest(http.MethodPost, "/cert/resign", bytes.NewReader(data))
	rec = httptest.NewRecorder()
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.certResign(c))
	assert.Equal(t, http.StatusOK, rec.Code)

}

func TestCertVerify(t *testing.T) {

	f, _ := os.Open("./testdata/cert_unsigned.pem")
	data, _ := io.ReadAll(f)
	data, _ = json.Marshal(&CACert{string(data)})

	// testing header missing
	req := httptest.NewRequest(http.MethodPost, "/cert/verify", bytes.NewReader(data))
	rec := httptest.NewRecorder()
	c := verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.certVerify(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// testing unsigned cert
	req = httptest.NewRequest(http.MethodPost, "/cert/Verify", bytes.NewReader(data))
	rec = httptest.NewRecorder()
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.certVerify(c))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// testing OK
	data, _ = json.Marshal(&cacert)
	req = httptest.NewRequest(http.MethodPost, "/cert/Verify", bytes.NewReader(data))
	rec = httptest.NewRecorder()
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.certVerify(c))
	assert.Equal(t, http.StatusOK, rec.Code)

}

func TestServerStart(t *testing.T) {
	verify.Start()
}

func TestCloseServer(t *testing.T) {
	assert.NoError(t, smtpServer.Stop())
}
