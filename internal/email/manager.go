package email

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/Cealgull/Verify/internal/cache"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

type EmailDialer struct {
	from     string
	secret   string
	todom    string
	template string
	client   *smtp.Client
}

type DialerOption func(dialer *EmailDialer) error

func WithDialerTemplate(template string) DialerOption {
	return func(dialer *EmailDialer) error {
		dialer.template = template
		return nil
	}
}

func WithClient(addr string) DialerOption {
	return func(dialer *EmailDialer) error {
		c, err := smtp.Dial(addr)
		if err != nil {
			return err
		}
		dialer.client = c
		return nil
	}
}

func WithFrom(account string, fromdom string, secret string) DialerOption {
	return func(dialer *EmailDialer) error {
		from := fmt.Sprintf("%s@%s", account, fromdom)
		dialer.from = from
		dialer.secret = secret
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
	msg := fmt.Sprintf(d.template, to, content)
	auth := sasl.NewPlainClient("", d.from, d.secret)
	err := d.client.Auth(auth)
	if err != nil {
		return err
	}
	err = d.client.SendMail(d.from, []string{to}, strings.NewReader(msg))
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
		err := option(&mgr)
		if err != nil {
			return nil, err
		}
	}
	return &mgr, nil
}

func (m *EmailManager) Sign(account string) (int, error) {
	code := rand.Intn(1000000)
	content := fmt.Sprintf(m.template, code)
	if !m.accexp.Match([]byte(account)) {
		return -1, fmt.Errorf("Err: Account format not valid.")
	}

	count, err := m.cache.Exists(account)

	if count != 0 {
		return -1, fmt.Errorf("Err: Verication Code has already been sent. Preventing Duplicates...")
	}

	if err != nil {
		return -1, fmt.Errorf("Err: Database Error")
	}

	if err := m.dialer.send(account, content); err != nil {
		return -1, err
	}

	if err := m.cache.Set(account, fmt.Sprintf("%06d", code), time.Duration(5)*time.Minute); err != nil {
		return -1, nil
	}

	return code, nil
}

func (m *EmailManager) Verify(account string, guess string) (bool, error) {

	if !m.codeexp.Match([]byte(guess)) {
		return false, fmt.Errorf("Err: Guessing code format not valid.")
	}

	if !m.accexp.Match([]byte(account)) {
		return false, fmt.Errorf("Err: Account format not valid.")
	}

	truth, err := m.cache.GetDel(account)

	if err != nil {
		return false, fmt.Errorf("Err: Account is not valid anymore. Please re-sign the verification code")
	}

	if guess == truth {
		return true, nil
	} else {
		return false, nil
	}

}

func (m *EmailManager) Close() {
	m.dialer.close()
}
