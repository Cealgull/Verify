package verify

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/Cealgull/Verify/internal/email"
	"github.com/Cealgull/Verify/internal/fabric"
	"github.com/Cealgull/Verify/internal/keyset"
	"github.com/Cealgull/Verify/pkg/turnstile"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type VerificationServer struct {
	addr string
	ec   *echo.Echo
	em   *email.EmailManager
	fm   *fabric.FabricManager
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
	Id     string `json:"id"`
	Secret string `json:"secret"`
}

func NewVerificationServer(addr string, em *email.EmailManager, fm *fabric.FabricManager, km *keyset.KeyManager, ts *turnstile.Turnstile) *VerificationServer {

	ec := echo.New()
	v := VerificationServer{addr, ec, em, fm, km, ts}
	v.ec.Use(middleware.Logger())
	v.ec.Use(middleware.Recover())
	v.ec.POST("/auth/verify", v.verify)
	v.ec.POST("/auth/register", v.register)
	v.ec.POST("/auth/sign", v.sign)
	return &v
}

func (v *VerificationServer) verify(c echo.Context) error {
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

func (v *VerificationServer) register(c echo.Context) error {
	var req RegisterRequest

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest,
			CodeMessage{http.StatusBadRequest, err.Error()})
	}

	sigb64 := c.Request().Header.Get("sig")

	if sigb64 == "" {
		return c.JSON(http.StatusBadRequest,
			CodeMessage{http.StatusBadRequest, "Err: Signature not found in headers"})
	}

	sig, err := base64.StdEncoding.DecodeString(sigb64)

	if err != nil || sig == nil {
		return c.JSON(http.StatusBadRequest,
			CodeMessage{http.StatusBadRequest,
				"Err: Signature invalid in type"})
	}

	msg, _ := json.Marshal(&req)

	success, _ := v.sm.Verify(msg, sig)

	if success {
		return c.JSON(http.StatusOK,
			CodeMessage{http.StatusOK, "OK"})
	} else {
		return c.JSON(http.StatusBadRequest,
			CodeMessage{http.StatusBadRequest,
				"Err: Signature not matching the content"})
	}

}

func (v *VerificationServer) sign(c echo.Context) error {

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

func (s *VerificationServer) Start() {
	s.ec.Logger.Error(s.ec.Start(s.addr))
}
