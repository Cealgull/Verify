package email

import (
	"fmt"
	"math/rand"
	"regexp"
	"time"

	"github.com/Cealgull/Verify/internal/cache"
	"github.com/Cealgull/Verify/internal/proto"
	mail "github.com/xhit/go-simple-mail/v2"
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

type EmailDialer struct {
	from    string
	todom   string
	subject string
	server  *mail.SMTPServer
}

type DialerOption func(dialer *EmailDialer) error

func WithSubject(subject string) DialerOption {
	return func(dialer *EmailDialer) error {
		dialer.subject = subject
		return nil
	}
}

func WithClient(host string, port int, from string, secret string) DialerOption {
	return func(dialer *EmailDialer) error {
		server := mail.NewSMTPClient()
		server.Port = port
		server.Host = host
		server.Username = from
		server.Password = secret
		server.KeepAlive = true
		dialer.server = server
		dialer.from = from
		return nil
	}
}

func WithToDom(todom string) DialerOption {
	return func(dialer *EmailDialer) error {
		dialer.todom = todom
		return nil
	}
}

func NewEmailDialer(options ...DialerOption) (*EmailDialer, error) {
	var dialer EmailDialer
	for _, option := range options {
		err := option(&dialer)
		var _ = err
	}
	return &dialer, nil
}

func (d *EmailDialer) send(account string, content string) error {
	to := fmt.Sprintf("%s@%s", account, d.todom)
	msg := mail.NewMSG()
	msg.SetFrom(d.from).
		AddTo(to).
		SetSubject(d.subject).
		SetBody(mail.TextPlain, content)

	client, err := d.server.Connect()

	if err != nil {
		return err
	}

	logger.Debugf("Sending verification code to account: %s.", account)

	err = msg.Send(client)

	return err
}

type EmailManager struct {
	dialer   *EmailDialer
	cache    cache.Cache
	codeexp  *regexp.Regexp
	accexp   *regexp.Regexp
	template string
}

type ManagerOption func(mgr *EmailManager) error

func WithEmailTemplate(template string) ManagerOption {
	return func(mgr *EmailManager) error {
		mgr.template = template
		return nil
	}
}

func WithCodeExp(rule string) ManagerOption {
	return func(mgr *EmailManager) error {
		var err error
		mgr.codeexp, err = regexp.Compile(rule)
		return err
	}
}

func WithAccExp(rule string) ManagerOption {
	return func(mgr *EmailManager) error {
		var err error
		mgr.accexp, err = regexp.Compile(rule)
		return err
	}
}

func WithCache(cache cache.Cache) ManagerOption {
	return func(mgr *EmailManager) error {
		mgr.cache = cache
		return nil
	}
}

func WithEmailDialer(dialer *EmailDialer) ManagerOption {
	return func(mgr *EmailManager) error {
		mgr.dialer = dialer
		return nil
	}
}

func NewEmailManager(options ...ManagerOption) (*EmailManager, error) {
	var mgr EmailManager
	for _, option := range options {
		var _ = option(&mgr)
	}

	l, _ := zap.NewProduction()
	logger = l.Sugar()

	return &mgr, nil
}

func (m *EmailManager) Sign(account string) (int, proto.VerifyError) {

	code := rand.Intn(1000000)
	content := fmt.Sprintf(m.template, code)

	logger.Infof("Signing verification code for %s.", account)

	if !m.accexp.Match([]byte(account)) {
		logger.Debugf("Format checking failure for account: %s", account)
		return -1, &AccountFormatError{}
	}

	count, err := m.cache.Exists(account)

	if err != nil {
		logger.Errorf("Redis failure when signing for %s.", account)
		return -1, &EmailInternalError{}
	}

	if count != 0 {
		logger.Debugf("Email code duplicated for account: %s.", account)
		return -1, &DuplicateEmailError{}
	}

	if err := m.dialer.send(account, content); err != nil {
		logger.Debugf("Email dialing for account: %s.", account)
		return -1, &EmailDialingError{}
	}

	if err := m.cache.Set(account, fmt.Sprintf("%06d", code), time.Duration(5)*time.Minute); err != nil {
		logger.Errorf("Redis failure for setting verifcation code buffer for account: %s.", account)
		return -1, &EmailInternalError{}
	}

	return code, nil
}

func (m *EmailManager) Verify(account string, guess string) (bool, proto.VerifyError) {

	logger.Infof("Verifying code for %s.", account)

	if !m.accexp.Match([]byte(account)) {
		logger.Debugf("Format checking error for account: %s.", account)
		return false, &AccountFormatError{}
	}

	if !m.codeexp.Match([]byte(guess)) {
		logger.Debugf("Format checking error for code: %s.", guess)
		return false, &CodeFormatError{}
	}

	truth, err := m.cache.Get(account)

	if _, ok := err.(*cache.InternalError); ok {
		logger.Errorf("Redis Failure when getting verification truth for guess: %s", guess)
		return false, &EmailInternalError{}
	} else if _, ok := err.(*cache.KeyError); ok {
		logger.Debugf("Account not signed for verification code: %s.", account)
		return false, &AccountNotFoundError{}
	}

	if guess != truth {
		logger.Infof("Code verfication failed for account: %s.", account)
		return false, &CodeIncorrectError{}
	}

	err = m.cache.Del(account)

	if _, ok := err.(*cache.InternalError); ok {
		logger.Errorf("Redis Failure when deleting verification truth for guess: %s", account)
		return false, &EmailInternalError{}
	}

	logger.Infof("Code verification succeeded for account: %s.", account)

	return true, nil

}
