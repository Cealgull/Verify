package verify

import (
	"fmt"
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

type CertRequest struct {
	Pub string `json:"pub"`
}

type CACert struct {
	Cert string `json:"cert"`
}

var berr *GenericBindingError = &GenericBindingError{}
var bsig *SignatureMissingError = &SignatureMissingError{}
var success *VerifySuccess = &VerifySuccess{}

func NewVerificationServer(host string, port int, em *email.EmailManager, cm *cert.CertManager, km *keyset.KeyManager, ts *turnstile.Turnstile) *VerificationServer {

	addr := fmt.Sprintf("%s:%d", host, port)
	ec := echo.New()
	v := VerificationServer{addr, ec, em, cm, km, ts}
	v.ec.Use(middleware.Logger())
	v.ec.Use(middleware.Recover())
	v.ec.POST("/email/sign", v.emailSign)
	v.ec.POST("/email/verify", v.emailVerify)
	v.ec.POST("/cert/sign", v.certSign)
	v.ec.POST("/cert/verify", v.certVerify)
	v.ec.POST("/cert/resign", v.certResign)
	return &v
}

func (v *VerificationServer) emailSign(c echo.Context) error {

	var req EmailRequest

	if c.Bind(&req) != nil {
		return c.JSON(berr.Status(), berr.Message())
	}

	_, err := v.em.Sign(req.Account)

	if err != nil {
		return c.JSON(err.Status(), err.Message())
	}

	return c.JSON(success.Status(), success.Message())
}

func (v *VerificationServer) emailVerify(c echo.Context) error {
	var req EmailRequest

	if c.Bind(&req) != nil {
		return c.JSON(berr.Status(), berr.Message())
	}

	success, err := v.em.Verify(req.Account, req.Code)

	if !success && err != nil {
		return c.JSON(err.Status(), berr.Message())
	}

	return c.JSON(http.StatusOK, v.sm.Dispatch())

}

func (v *VerificationServer) certSign(c echo.Context) error {
	var req CertRequest

	if c.Bind(&req) != nil {
		return c.JSON(berr.Status(), berr.Message())
	}

	sigb64 := c.Request().Header.Get("signature")

	//TODO: Remove it when client side wasm support is done.

	if sigb64 != "HACK" {
		if sigb64 == "" {
			return c.JSON(bsig.Status(), bsig.Message())
		}

		ok, err := v.sm.Verify(req.Pub, sigb64)

		if !ok && err != nil {
			return c.JSON(err.Status(), err.Message())
		}
	}

	cert, err := v.cm.SignCSR(req.Pub)

	if err != nil {
		return c.JSON(err.Status(), err.Message())
	}

	return c.JSON(http.StatusOK, CACert{string(cert)})
}

func (v *VerificationServer) certResign(c echo.Context) error {
	var req CertRequest

	if c.Bind(&req) != nil {
		return c.JSON(berr.Status(), berr.Message())
	}

	cert, err := v.cm.ResignCSR(req.Pub)

	if err != nil {
		return c.JSON(err.Status(), err.Message())
	}

	return c.JSON(success.Status(), CACert{string(cert)})

}

func (v *VerificationServer) certVerify(c echo.Context) error {
	var req CACert

	if c.Bind(&req) != nil {
		return c.JSON(berr.Status(), berr.Message())
	}

	ok, err := v.cm.VerifyCert([]byte(req.Cert))

	if !ok && err != nil {
		return c.JSON(err.Status(), err.Message())
	}

	return c.JSON(success.Status(), success.Message())

}

func (s *VerificationServer) Start() {
	s.ec.Logger.Error(s.ec.Start(s.addr))
}
