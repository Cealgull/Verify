package email

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/Cealgull/Verify/internal/cache"
	mockcache "github.com/Cealgull/Verify/internal/cache/mock"
	"github.com/Cealgull/Verify/internal/proto"
	mocksmtp "github.com/mocktools/go-smtp-mock/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

var server *mocksmtp.Server
var mgr *EmailManager
var c *mockcache.MockCache
var code int

func TestFailedDialer(t *testing.T) {

	l, _ := zap.NewProduction()
	dialer, err := NewEmailDialer(
		l.Sugar(),
		WithClient("localhost", 0, "abcd", "abcd"),
	)

	assert.Nil(t, err)
	err = dialer.send("somebody", "hello world")
	assert.NotNil(t, err)
}

func TestNewEmailManager(t *testing.T) {

	l, _ := zap.NewProduction()

	server = mocksmtp.New(mocksmtp.ConfigurationAttr{
		PortNumber:              2333,
		LogToStdout:             false,
		LogServerActivity:       false,
		BlacklistedRcpttoEmails: []string{"user3@example2.org"},
	})

	err := server.Start()
	assert.Nil(t, err)

	var dialer *EmailDialer

	dialer, err = NewEmailDialer(
		l.Sugar(),
		WithClient("localhost", 2333, "admin@sjtu.edu.cn", "secret"),
		WithToDom("example2.org"),
		WithSubject("Verification Code"),
	)

	assert.Nil(t, err)

	c = mockcache.NewMockCache()

	mgr, err = NewEmailManager(
		l.Sugar(),
		WithEmailDialer(dialer),
		WithEmailTemplate("The Verification is %06d"),
		WithAccExp("^[a-zA-Z0-9-_\\.]{3,50}$"),
		WithCodeExp("^\\d{6}$"),
		WithCache(c),
	)

	if err != nil {
		panic(err)
	}

}

func TestEmailSign(t *testing.T) {
	var err proto.VerifyError
	code, err = mgr.Sign("user1")
	assert.Nil(t, err)

	code, err = mgr.Sign("user1")
	assert.IsType(t, &DuplicateEmailError{}, err)
	var _ = err.Status()
	var _ = err.Message()

	c.AddGetErr("user1", &cache.InternalError{})
	_, err = mgr.Sign("user1")
	assert.IsType(t, &EmailInternalError{}, err)
	var _ = err.Status()
	var _ = err.Message()

	_, err = mgr.Sign("@ssjft=")
	assert.IsType(t, &AccountFormatError{}, err)
	var _ = err.Status()
	var _ = err.Message()

	c.AddSetErr("user2", &cache.InternalError{})
	_, err = mgr.Sign("user2")
	assert.IsType(t, &EmailInternalError{}, err)
	var _ = err.Status()
	var _ = err.Message()

	_, err = mgr.Sign("user3")
	assert.IsType(t, &EmailDialingError{}, err)
	var _ = err.Status()
	var _ = err.Message()

	code, err = mgr.Sign("user4")
	assert.Nil(t, err)
}

func TestEmailVerify(t *testing.T) {

	var f bool

	_, err := mgr.Verify("@!sag", "asfhasufd")
	assert.IsType(t, &AccountFormatError{}, err)

	_, err = mgr.Verify("user1", "ashfusiadg")
	assert.IsType(t, &CodeFormatError{}, err)
	fmt.Println(err.Status(), err.Message())

	_, err = mgr.Verify("user1", "123456")
	assert.IsType(t, &EmailInternalError{}, err)

	_, err = mgr.Verify("user5", "234567")
	assert.IsType(t, &AccountNotFoundError{}, err)
	fmt.Println(err.Status(), err.Message())

	var guess int

	for {
		guess = rand.Intn(100000)
		if code != guess {
			break
		}
	}

	f, err = mgr.Verify("user4", fmt.Sprintf("%06d", guess))
	var _ = err.Status()
	var _ = err.Message()
	assert.False(t, f)

	f, _ = mgr.Verify("user4", fmt.Sprintf("%06d", code))
	assert.True(t, f)

	_, err = mgr.Verify("user4", fmt.Sprintf("%06d", code))
	assert.IsType(t, &AccountNotFoundError{}, err)

	c.AddDelErr("user6", &cache.InternalError{})

	code, _ = mgr.Sign("user6")
	_, err = mgr.Verify("user6", fmt.Sprintf("%06d", code))

	assert.IsType(t, &EmailInternalError{}, err)

}

func TestCloseServer(t *testing.T) {
	assert.NoError(t, server.Stop())
}
