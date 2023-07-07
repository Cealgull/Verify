package email

import (
	"fmt"
	"math/rand"
	"regexp"
	"time"

	"github.com/Cealgull/Verify/internal/cache"
	"github.com/Cealgull/Verify/internal/proto"
	mail "github.com/xhit/go-simple-mail/v2"
)

type EmailDialer struct {
	from    string
	todom   string
	subject string
	client  *mail.SMTPClient
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

		var err error
		dialer.client, err = server.Connect()
		dialer.from = from
		return err
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
		if err != nil {
			return nil, err
		}
	}
	return &dialer, nil
}

func (d *EmailDialer) close() {
	d.client.Close()
}

func (d *EmailDialer) send(account string, content string) error {
	to := fmt.Sprintf("%s@%s", account, d.todom)
	msg := mail.NewMSG()
	msg.SetFrom(d.from).
		AddTo(to).
		SetSubject(d.subject).
		SetBody(mail.TextPlain, content)

	err := msg.Send(d.client)

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
	return &mgr, nil
}

func (m *EmailManager) Sign(account string) (int, proto.VerifyError) {
	code := rand.Intn(1000000)
	content := fmt.Sprintf(m.template, code)
	if !m.accexp.Match([]byte(account)) {
		return -1, &AccountError{}
	}

	count, err := m.cache.Exists(account)

	if err != nil {
		return -1, &InternalError{}
	}

	if count != 0 {
		return -1, &DuplicateError{}
	}

	if err := m.dialer.send(account, content); err != nil {
		return -1, &InternalError{}
	}

	if err := m.cache.Set(account, fmt.Sprintf("%06d", code), time.Duration(5)*time.Minute); err != nil {
		return -1, &InternalError{}
	}

	return code, nil
}

func (m *EmailManager) Verify(account string, guess string) (bool, proto.VerifyError) {

	if !m.accexp.Match([]byte(account)) {
		return false, &AccountError{}
	}

	if !m.codeexp.Match([]byte(guess)) {
		return false, &CodeError{}
	}

	truth, err := m.cache.Get(account)

	if _, ok := err.(*cache.InternalError); ok {
		return false, &InternalError{}
	} else if _, ok := err.(*cache.KeyError); ok {
		return false, &NotFoundError{}
	}

	if guess != truth {
		return false, nil
	}

	err = m.cache.Del(account)

	if _, ok := err.(*cache.InternalError); ok {
		return false, &InternalError{}
	}

	return true, nil

}

func (m *EmailManager) Close() {
	m.dialer.close()
}
