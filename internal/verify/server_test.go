package verify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mockcache "github.com/Cealgull/Verify/internal/cache/mock"
	"github.com/Cealgull/Verify/internal/cert"
	"github.com/Cealgull/Verify/internal/email"
	"github.com/Cealgull/Verify/internal/keyset"
	"github.com/Cealgull/Verify/pkg/keypair"
	"github.com/Cealgull/Verify/pkg/turnstile"
	"github.com/labstack/echo/v4"
	mocksmtp "github.com/mocktools/go-smtp-mock/v2"
	"github.com/stretchr/testify/assert"
)

var smtpServer *mocksmtp.Server
var cache *mockcache.MockCache
var verify *VerificationServer
var dialer *email.EmailDialer
var kp keypair.KeyPair
var errjson = "114514"
var code string

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

	cache = mockcache.NewMockCache()

	em, err := email.NewEmailManager(
		email.WithEmailDialer(dialer),
		email.WithCache(cache),
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
	)

	assert.NoError(t, err)

	verify = NewVerificationServer("localhost1:9999", em, cm, km, ts)

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
	code, err = cache.Get("user1")
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
	data, err := io.ReadAll(rec.Body)
	assert.NoError(t, err)
	assert.NoError(t, json.Unmarshal(data, &kp))
}

func TestServerStart(t *testing.T) {
	verify.Start()
}

func TestCloseServer(t *testing.T) {
	assert.NoError(t, smtpServer.Stop())
}
