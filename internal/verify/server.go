package verify

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"github.com/Cealgull/Verify/internal/email"
	"github.com/Cealgull/Verify/internal/fabric"
	"github.com/Cealgull/Verify/internal/keyset"
	"github.com/Cealgull/Verify/pkg/turnstile"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type VerificationServer struct {
	host string
	port string
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

func New(host string, port string, em *email.EmailManager, fm *fabric.FabricManager, km *keyset.KeyManager, ts *turnstile.Turnstile) *VerificationServer {

	ec := echo.New()
	v := VerificationServer{host, port, ec, em, fm, km, ts}
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
		return c.JSON(http.StatusInternalServerError,
			CodeMessage{http.StatusInternalServerError, err.Error()})
	}
	success, err := v.em.Verify(req.Account, req.Code)
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			CodeMessage{http.StatusInternalServerError, err.Error()})
	}
	if success {
		token := v.sm.Dispatch()
		return c.JSON(http.StatusOK, &token)
	} else {
		return c.JSON(http.StatusNotFound, CodeMessage{
			http.StatusNotFound,
			"Err: Verification Failed for current account",
		})
	}
}

func (v *VerificationServer) register(c echo.Context) error {
	var req RegisterRequest

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest,
			CodeMessage{http.StatusBadRequest, err.Error()})
	}

	signature, err := hex.DecodeString(c.Request().Header.Get("Signature"))

	if err != nil || signature == nil {
		return c.JSON(http.StatusBadRequest,
			CodeMessage{http.StatusBadRequest,
				"Err: Signature not found in headers"})
	}

	body, err := io.ReadAll(c.Request().Body)

	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			CodeMessage{http.StatusInternalServerError, err.Error()})
	}
	success, err := v.sm.Verify(body, []byte(signature))

	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			CodeMessage{http.StatusInternalServerError, err.Error()})
	}

	if success {
		return c.JSON(http.StatusOK,
			CodeMessage{http.StatusOK, "OK"})
	} else {
		return c.JSON(http.StatusInternalServerError,
			CodeMessage{http.StatusInternalServerError,
				"Err: Signature not matching the content"})
	}

}

func (v *VerificationServer) sign(c echo.Context) error {

	req := new(EmailRequest)

	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusInternalServerError,
			CodeMessage{http.StatusInternalServerError, err.Error()})
	}

	_, err := v.em.Sign(req.Account)

	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			CodeMessage{http.StatusInternalServerError, err.Error()})
	}

	return c.JSON(http.StatusOK,
		CodeMessage{http.StatusOK, "OK"})

}

func (s *VerificationServer) Start() {
	s.ec.Logger.Fatal(s.ec.Start(fmt.Sprintf("%s:%s", s.host, s.port)))
}
