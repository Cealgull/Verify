package main

import (
	"github.com/Cealgull/Verify/internal/cache"
	"github.com/Cealgull/Verify/internal/cert"
	"github.com/Cealgull/Verify/internal/config"
	"github.com/Cealgull/Verify/internal/email"
	"github.com/Cealgull/Verify/internal/keyset"
	"github.com/Cealgull/Verify/internal/verify"
	"github.com/Cealgull/Verify/pkg/turnstile"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func main() {

	logger, _ := zap.NewProduction()

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/cealgull-verify")
	viper.AddConfigPath("./configs/")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()

	if err != nil {
		logger.Panic(err.Error())
	}

	var conf config.VerifyConfig

	err = viper.Unmarshal(&conf)

	if err != nil {
		logger.Panic(err.Error())
	}

	dialer, err := email.NewEmailDialer(
		email.WithClient(conf.Email.Dialer.Host,
			conf.Email.Dialer.Port,
			conf.Email.Dialer.From,
			conf.Email.Dialer.Secret),
		email.WithToDom(conf.Email.Dialer.Todom),
		email.WithSubject(conf.Email.Dialer.Subject),
	)

	if err != nil {
		logger.Panic(err.Error())
	}

	c := cache.NewRedis(conf.Email.Redis.Host,
		conf.Email.Redis.Port,
		conf.Email.Redis.User,
		conf.Email.Redis.Secret,
		conf.Email.Redis.DB)

	em, err := email.NewEmailManager(
		email.WithCodeExp(conf.Email.Coderule),
		email.WithEmailDialer(dialer),
		email.WithCache(c),
		email.WithAccExp(conf.Email.Accrule),
		email.WithEmailTemplate(conf.Email.Template),
	)

	if err != nil {
		logger.Panic(err.Error())
	}

	c = cache.NewRedis(conf.Email.Redis.Host,
		conf.Email.Redis.Port,
		conf.Email.Redis.User,
		conf.Email.Redis.Secret,
		(conf.Email.Redis.DB+1)%10,
	)

	cm, err := cert.NewCertManager(
		cert.WithPrivateKey(conf.Cert.Priv),
		cert.WithCertificate(conf.Cert.Cert),
		cert.WithCache(c),
	)

	if err != nil {
		logger.Panic(err.Error())
	}

	km, err := keyset.NewKeyManager(
		conf.Keyset.NR_mem,
		conf.Keyset.Cap,
	)

	if err != nil {
		logger.Panic(err.Error())
	}

	ts := turnstile.NewTurnstile(conf.Turnstile.Secret)

	server := verify.NewVerificationServer(
		conf.Verify.Host, conf.Verify.Port,
		em, cm, km, ts)

	server.Start()
}
