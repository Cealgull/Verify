package email

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/Cealgull/Verify/internal/cache"
	mockcache "github.com/Cealgull/Verify/internal/cache/mock"
	mocksmtp "github.com/mocktools/go-smtp-mock/v2"
	"github.com/stretchr/testify/assert"
)

var server *mocksmtp.Server
var mgr *EmailManager
var c *mockcache.MockCache
var code int

func TestNewEmailManager(t *testing.T) {

	server = mocksmtp.New(mocksmtp.ConfigurationAttr{
		PortNumber:              2333,
		LogToStdout:             false,
		LogServerActivity:       false,
		BlacklistedRcpttoEmails: []string{"user3@example2.org"},
	})

	err := server.Start()
	assert.Nil(t, err)

	var dialer *EmailDialer

	_, err = NewEmailDialer(
		WithClient("localhost", 0, "abcd", "abcd"),
	)

	assert.NotNil(t, err)

	dialer, err = NewEmailDialer(
		WithClient("localhost", 2333, "user1@example.org", "secret"),
		WithToDom("example2.org"),
		WithSubject("Verification Code"),
	)

	assert.Nil(t, err)

	c = mockcache.NewMockCache()

	mgr, err = NewEmailManager(
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
	var err error
	code, err = mgr.Sign("user1")
	assert.Nil(t, err)

	code, err = mgr.Sign("user1")
	assert.IsType(t, &DuplicateError{}, err)
	fmt.Println(err.(*DuplicateError).Code(), err.(*DuplicateError).Error())

	c.AddGetErr("user1", &cache.InternalError{})
	_, err = mgr.Sign("user1")
	assert.IsType(t, &InternalError{}, err)
	fmt.Println(err.(*InternalError).Code(), err.(*InternalError).Error())

	_, err = mgr.Sign("@ssjft=")
	assert.IsType(t, &AccountError{}, err)
	fmt.Println(err.(*AccountError).Code(), err.(*AccountError).Error())

	c.AddSetErr("user2", &cache.InternalError{})
	_, err = mgr.Sign("user2")
	assert.IsType(t, &InternalError{}, err)

	_, err = mgr.Sign("user3")
	assert.IsType(t, &InternalError{}, err)

	code, err = mgr.Sign("user4")
	assert.Nil(t, err)
}

func TestEmailVerify(t *testing.T) {

	var f bool

	_, err := mgr.Verify("@!sag", "asfhasufd")
	assert.IsType(t, &AccountError{}, err)

	_, err = mgr.Verify("user1", "ashfusiadg")
	assert.IsType(t, &CodeError{}, err)
	fmt.Println(err.(*CodeError).Code(), err.(*CodeError).Error())

	_, err = mgr.Verify("user1", "123456")
	assert.IsType(t, &InternalError{}, err)

	_, err = mgr.Verify("user5", "234567")
	assert.IsType(t, &NotFoundError{}, err)
	fmt.Println(err.(*NotFoundError).Code(), err.(*NotFoundError).Error())

	var guess int

	for {
		guess = rand.Intn(100000)
		if code != guess {
			break
		}
	}

	f, _ = mgr.Verify("user4", fmt.Sprintf("%06d", guess))
	assert.False(t, f)

	f, _ = mgr.Verify("user4", fmt.Sprintf("%06d", code))
	assert.True(t, f)

	_, err = mgr.Verify("user4", fmt.Sprintf("%06d", code))
	assert.IsType(t, &NotFoundError{}, err)

	c.AddDelErr("user6", &cache.InternalError{})

	code, _ = mgr.Sign("user6")
	_, err = mgr.Verify("user6", fmt.Sprintf("%06d", code))

	assert.IsType(t, &InternalError{}, err)

}

func TestCloseServer(t *testing.T) {
	assert.NoError(t, server.Stop())
}
