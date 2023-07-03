package verify

import (
	"encoding/hex"
	"fmt"
	"io"
	"strconv"

	"github.com/Cealgull/Verify/internal/email"
	"github.com/Cealgull/Verify/internal/fabric"
	"github.com/Cealgull/Verify/internal/sign"
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
	sm   *sign.SignManager
	ts   *turnstile.Turnstile
}

type EmailRequest struct {
	Account string `json:"account"`
	Code    int    `json:"code,omitempty"`
}

type CodeMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type RegisterRequest struct {
	Id     string `json:"id"`
	Secret string `json:"secret"`
}

func New(host string, port string, em *email.EmailManager, fm *fabric.FabricManager, sm *sign.SignManager, ts *turnstile.Turnstile) *VerificationServer {

	ec := echo.New()
	v := VerificationServer{host, port, ec, em, fm, sm, ts}
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
		return c.JSON(500, CodeMessage{500, err.Error()})
	}
	success, err := v.em.Verify(req.Account, strconv.Itoa(req.Code))
	if err != nil {
		return c.JSON(500, CodeMessage{500, err.Error()})
	}
	if success {
		return c.JSON(200, v.sm.Dispatch())
	} else {
		return c.JSON(404, CodeMessage{
			404,
			"Err: Verification Failed for current account",
		})
	}
}

func (v *VerificationServer) register(c echo.Context) error {
	var req RegisterRequest

	if err := c.Bind(&req); err != nil {
		return c.JSON(500, CodeMessage{500, err.Error()})
	}

	signature, err := hex.DecodeString(c.Request().Header.Get("Signature"))

	if err != nil || signature == nil {
		return c.JSON(500, CodeMessage{500, "Err: Signature not found in headers"})
	}

	body, err := io.ReadAll(c.Request().Body)

	if err != nil {
		return c.JSON(500, CodeMessage{500, err.Error()})
	}

	success, err := v.sm.Verify(body, []byte(signature))

	if err != nil {
		return c.JSON(500, CodeMessage{500, err.Error()})
	}

	if success {
		return c.JSON(200, CodeMessage{200, "OK"})
	} else {
		return c.JSON(500, CodeMessage{500, "Err: Signature not matching the content"})
	}

}

func (v *VerificationServer) sign(c echo.Context) error {

	var req EmailRequest

	if err := c.Bind(&req); err != nil {
		return c.JSON(500, CodeMessage{500, err.Error()})
	}
	_, err := v.em.Sign(req.Account)

	if err != nil {
		return c.JSON(500, CodeMessage{500, err.Error()})
	}

	return c.JSON(200, CodeMessage{200, "OK"})

}

func (s *VerificationServer) Start() {
	s.ec.Logger.Fatal(s.ec.Start(fmt.Sprintf("%s:%s", s.host, s.port)))
}
