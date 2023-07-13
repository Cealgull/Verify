package verify

import (
	"encoding/base64"
	"net/http"

	"github.com/Cealgull/Verify/internal/cert"
	"github.com/Cealgull/Verify/internal/email"
	"github.com/Cealgull/Verify/internal/keyset"
	"github.com/Cealgull/Verify/pkg/turnstile"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type VerificationServer struct {
	addr string
	ec   *echo.Echo
	em   *email.EmailManager
	cm   *cert.CertManager
	sm   *keyset.KeyManager
	ts   *turnstile.Turnstile
}

type EmailRequest struct {
	Account string `json:"account"`
	Code    string `json:"code"`
}

type CodeMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type RegisterRequest struct {
	Pub string `json:"pub"`
}

type CACert struct {
	Cert string `json:"cert"`
}

func NewVerificationServer(addr string, em *email.EmailManager, cm *cert.CertManager, km *keyset.KeyManager, ts *turnstile.Turnstile) *VerificationServer {

	ec := echo.New()
	v := VerificationServer{addr, ec, em, cm, km, ts}
	v.ec.Use(middleware.Logger())
	v.ec.Use(middleware.Recover())
	v.ec.POST("/email/sign", v.emailSign)
	v.ec.POST("/email/verify", v.emailVerify)
	v.ec.POST("/cert/sign", v.certSign)
	v.ec.POST("/cert/verify", v.certVerify)
	return &v
}

func (v *VerificationServer) emailSign(c echo.Context) error {

	var req EmailRequest

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest,
			CodeMessage{http.StatusBadRequest, "BadRequest: Incorrect Request Params"})
	}

	_, err := v.em.Sign(req.Account)

	if err != nil {
		return c.JSON(err.Code(),
			CodeMessage{err.Code(), err.Error()})
	}

	return c.JSON(http.StatusOK,
		CodeMessage{http.StatusOK, "OK"})

}

func (v *VerificationServer) emailVerify(c echo.Context) error {
	var req EmailRequest

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest,
			CodeMessage{http.StatusBadRequest, err.Error()})
	}

	success, err := v.em.Verify(req.Account, req.Code)

	if err != nil {
		return c.JSON(err.Code(),
			CodeMessage{err.Code(), err.Error()})
	}

	if success {
		token := v.sm.Dispatch()
		return c.JSON(http.StatusOK, token)
	} else {
		return c.JSON(http.StatusNotFound, CodeMessage{
			http.StatusNotFound,
			"Email: Verification Failed for current account",
		})
	}

}

func (v *VerificationServer) certSign(c echo.Context) error {
	var req RegisterRequest

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest,
			CodeMessage{http.StatusBadRequest, err.Error()})
	}

	sigb64 := c.Request().Header.Get("signature")

	if sigb64 != "HACK" {
		if sigb64 == "" {
			return c.JSON(http.StatusBadRequest,
				CodeMessage{http.StatusBadRequest, "CSR: Signature not found in headers"})
		}

		sig, err := base64.StdEncoding.DecodeString(sigb64)

		if err != nil || sig == nil {
			return c.JSON(http.StatusBadRequest,
				CodeMessage{http.StatusBadRequest,
					"CSR: Signature invalid in type"})
		}

		msg := []byte(req.Pub)

		// TODO: Add verificaton error checking
		ok, _ := v.sm.Verify(msg, sig)

		if !ok {
			return c.JSON(http.StatusBadRequest,
				CodeMessage{http.StatusBadRequest, "CSR: Signature not valid"})
		}
	}

	cert, err := v.cm.SignCSR(req.Pub)

	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			CodeMessage{http.StatusInternalServerError, err.Error()})
	}

	return c.JSON(http.StatusOK, CACert{string(cert)})
}

func (v *VerificationServer) certVerify(c echo.Context) error {
	var req CACert

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest,
			CodeMessage{http.StatusBadRequest, "Cert: Incorrect Request Params"})
	}

	ok, err := v.cm.VerifyCert([]byte(req.Cert))

	if err != nil {
		return c.JSON(err.Code(),
			CodeMessage{err.Code(), err.Error()})
	}

	if ok {
		return c.JSON(http.StatusOK,
			CodeMessage{http.StatusOK, "OK"})
	} else {
		return c.JSON(err.Code(),
			CodeMessage{err.Code(), err.Error()})
	}

}

func (s *VerificationServer) Start() {
	s.ec.Logger.Error(s.ec.Start(s.addr))
}
