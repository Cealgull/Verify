package email

import (
	"context"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/redis/go-redis/v9"
)

type EmailDialer struct {
	from      string
	dstdomain string
	template  string
	client    *smtp.Client
}

func NewEmailDialer(fromdom string, todom string, addr string, template string) (*EmailDialer, error) {
	c, err := smtp.Dial(addr)
	if err != nil {
		return nil, err
	}
	from := fmt.Sprintf("%s@%s", "noreply", fromdom)
	d := EmailDialer{from, todom, template, c}
	return &d, nil
}

func (d *EmailDialer) close() {
	d.client.Close()
}

func (d *EmailDialer) send(account string, content string) error {
	to := fmt.Sprintf("%s@%s", account, d.dstdomain)
	msg := fmt.Sprintf(d.template, to, content)
	err := d.client.SendMail(d.from, []string{to}, strings.NewReader(msg))
	return err
}

type EmailManager struct {
	dialer   *EmailDialer
	rclient  *redis.Client
	codeexp  *regexp.Regexp
	accexp   *regexp.Regexp
	template string
}

type ManagerOption struct {
	codeexp  *regexp.Regexp
	accexp   *regexp.Regexp
	redis    *redis.Client
	dialer   *EmailDialer
	template string
}

type Option func(opts *ManagerOption) error

func WithTemplate(template string) Option {
	return func(opts *ManagerOption) error {
		opts.template = template
		return nil
	}
}

func WithCodeExp(rule string) Option {
	return func(opts *ManagerOption) error {
		var err error
		opts.codeexp, err = regexp.Compile(rule)
		return err
	}
}

func WithAccExp(rule string) Option {
	return func(opts *ManagerOption) error {
		var err error
		opts.accexp, err = regexp.Compile(rule)
		return err
	}
}

func WithRedis(host string, port string, user string, secret string, index int) Option {
	return func(opts *ManagerOption) error {
		opts.redis = redis.NewClient(
			&redis.Options{
				Addr:     fmt.Sprintf("%s:%s", host, port),
				Username: user,
				Password: secret,
				DB:       index,
			},
		)
		return nil
	}
}

func WithEmailDialer(dialer *EmailDialer) Option {
	return func(opts *ManagerOption) error {
		opts.dialer = dialer
		return nil
	}
}

func new(opts *ManagerOption) EmailManager {
	return EmailManager{
		dialer:   opts.dialer,
		accexp:   opts.accexp,
		codeexp:  opts.codeexp,
		template: opts.template,
	}
}

func New(opts ...Option) (*EmailManager, error) {
	var option ManagerOption
	for _, f := range opts {
		err := f(&option)
		if err != nil {
			return nil, err
		}
	}
	m := new(&option)
	return &m, nil
}

func (m *EmailManager) Sign(account string) (int, error) {
	code := rand.Intn(6)
	content := fmt.Sprintf(m.template, code)
	if !m.accexp.Match([]byte(account)) {
		return -1, fmt.Errorf("Invalid account. Do you really want to hijack the services?")
	}

	ctx := context.Background()
	err := m.rclient.Get(ctx, account).Err()

	if err != redis.Nil {
		return -1, fmt.Errorf("Verification code has already been sent. Please wait for expiration.")
	}

	err = m.dialer.send(account, content)
	if err != nil {
		return -1, nil
	}

	err = m.rclient.Set(ctx, account, fmt.Sprintf("%06d", code), time.Duration(3)*time.Minute).Err()

	if err != nil {
		return -1, err
	}

	return code, nil
}

func (m *EmailManager) Verify(account string, guess string) (bool, error) {

	if !m.codeexp.Match([]byte(guess)) {
		return false, fmt.Errorf("Guessing code format not valid.")
	}

	if !m.accexp.Match([]byte(account)) {
		return false, fmt.Errorf("Invalid account. Do you really want to hijack the services?")
	}

	ctx := context.Background()
	cmd := m.rclient.GetDel(ctx, account)
	err := cmd.Err()

	if err == redis.Nil {
		return false, fmt.Errorf("Account not found.")
	} else if err != nil {
		return false, err
	}

	truth := cmd.String()
	if guess == truth {
		return true, nil
	} else {
		return false, nil
	}
}

func (m *EmailManager) Close() {
	m.dialer.close()
}
