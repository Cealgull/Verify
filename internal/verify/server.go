package verify

import (
	"fmt"
	"net/http"

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

func New(host string, port string, em *email.EmailManager, fm *fabric.FabricManager, sm *sign.SignManager, ts *turnstile.Turnstile) *VerificationServer {

	ec := echo.New()
	v := VerificationServer{host, port, ec, em, fm, sm, ts}
	v.ec.Use(middleware.Logger())
	v.ec.Use(middleware.Recover())
	v.ec.GET("/verify", v.verify)
	v.ec.GET("/register", v.register)
	v.ec.GET("/sign", v.sign)
	return &v
}

func (v *VerificationServer) verify(c echo.Context) error {
	return c.String(http.StatusOK, "this is a verifcation route for email code, sending signed auth token")
}

func (v *VerificationServer) register(c echo.Context) error {
	return c.String(http.StatusOK, "verify auth token in zero knowledge membership proof style and ask fabric to enroll the identity")
}

func (s *VerificationServer) sign(c echo.Context) error {
	return c.String(http.StatusOK, "generate an authorization code and invoke email service api, send the code to the requester")
}

func (s *VerificationServer) Start() {
	s.ec.Logger.Fatal(s.ec.Start(fmt.Sprintf("%s:%s", s.host, s.port)))
}
