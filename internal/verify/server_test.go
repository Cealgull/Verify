package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mockcache "github.com/Cealgull/Verify/internal/cache/mock"
	"github.com/Cealgull/Verify/internal/email"
	"github.com/Cealgull/Verify/internal/fabric"
	"github.com/Cealgull/Verify/internal/keyset"
	"github.com/Cealgull/Verify/pkg/keypair"
	"github.com/Cealgull/Verify/pkg/turnstile"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/mocks"
	"github.com/hyperledger/fabric-sdk-go/pkg/msp/test/mockmsp"
	"github.com/labstack/echo/v4"
	mocksmtp "github.com/mocktools/go-smtp-mock/v2"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/anon"
)

var smtpServer *mocksmtp.Server
var caServer *mockmsp.MockFabricCAServer
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

	assert.Nil(t, err)

    lis, err := net.Listen("tcp", "127.0.0.1:2333")
	caServer = &mockmsp.MockFabricCAServer{}
	suite := &mocks.MockCryptoSuite{}
	caServer.Start(lis, suite)
	assert.Nil(t, err)

	cache = mockcache.NewMockCache()

	em, err := email.NewEmailManager(
		email.WithEmailDialer(dialer),
		email.WithCache(cache),
		email.WithAccExp("^[a-zA-Z0-9-_\\.]{3,50}$"),
		email.WithEmailTemplate("this is a testing code %06d"),
		email.WithCodeExp("^[0-9]{6}$"),
	)
	assert.Nil(t, err)
	fm, err := fabric.NewFabricManager(
		fabric.WithConfiguration("./testdata/ccp_mock.yaml"),
		fabric.WithOrg("Org1"),
		fabric.WithCAHost("ca.org1.example.com"),
	)
	assert.Nil(t, err)

	km, err := keyset.NewKeyManager(16, 16)
	assert.Nil(t, err)

	ts := turnstile.NewTurnstile("secret")

	verify = NewVerificationServer("localhost1:9999", em, fm, km, ts)

}

func TestSignHandler(t *testing.T) {

	req := httptest.NewRequest(http.MethodPost, "/auth/sign", strings.NewReader(errjson))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := verify.ec.NewContext(req, rec)

	assert.NoError(t, verify.sign(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	signRequest := EmailRequest{
		Account: "@!#@",
		Code:    "",
	}

	data, _ := json.Marshal(&signRequest)

	req = httptest.NewRequest(http.MethodPost, "/auth/sign", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.sign(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	signRequest = EmailRequest{
		Account: "user1",
		Code:    "",
	}

	data, _ = json.Marshal(&signRequest)

	req = httptest.NewRequest(http.MethodPost, "/auth/sign", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.sign(c))

	var err error
	code, err = cache.Get("user1")
	assert.NoError(t, err)
}

func TestVerifyHandler(t *testing.T) {

	req := httptest.NewRequest(http.MethodPost, "/auth/verify", strings.NewReader(errjson))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.verify(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	signRequest := EmailRequest{
		Account: "@!##$",
	}

	data, _ := json.Marshal(&signRequest)

	req = httptest.NewRequest(http.MethodPost, "/auth/verify", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.verify(c))

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

	req = httptest.NewRequest(http.MethodPost, "/auth/verify", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.verify(c))

	assert.Equal(t, http.StatusNotFound, rec.Code)

	signRequest = EmailRequest{
		Account: "user1",
		Code:    code,
	}

	data, _ = json.Marshal(&signRequest)

	req = httptest.NewRequest(http.MethodPost, "/auth/verify", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.verify(c))

	assert.Equal(t, http.StatusOK, rec.Code)
	data, err := io.ReadAll(rec.Body)
	assert.NoError(t, err)
	assert.NoError(t, json.Unmarshal(data, &kp))
}

func TestRegisterHandler(t *testing.T) {

	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(errjson))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.register(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	registerRequest := RegisterRequest{
		Id:     "user1",
		Secret: "user1",
	}

	data, _ := json.Marshal(&registerRequest)

	req = httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.register(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	req = httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("sig", "acbdeaf@==")
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.register(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	req = httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("sig", "YWJjZAo=")
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.register(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	sig := anon.Sign(edwards25519.NewBlakeSHA256Ed25519(), data, kp.Pubs, nil, kp.Idx, kp.Priv)
	sigb64 := base64.StdEncoding.EncodeToString(sig)
	req = httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(data))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set("sig", sigb64)
	rec = httptest.NewRecorder()
	c = verify.ec.NewContext(req, rec)
	assert.NoError(t, verify.register(c))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServerStart(t *testing.T){
    verify.Start()
}

func TestCloseServer(t *testing.T) {
    smtpServer.Stop()
}
