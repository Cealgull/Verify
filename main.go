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

	logger, _ := zap.NewProduction(
		zap.WithCaller(true),
	)

	logger.Debug("Loading Verification Server Configuration.")

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/cealgull-verify")
	viper.AddConfigPath("./configs/")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()

	if err != nil {
		logger.Panic(err.Error())
	}

	var vericonf config.VerifyConfig

	err = viper.Unmarshal(&vericonf)

	if err != nil {
		logger.Panic(err.Error())
	}

	logger.Debug("Initializing the email dialer.")

	dialer, err := email.NewEmailDialer(
		email.WithClient(vericonf.Email.Dialer.Host,
			vericonf.Email.Dialer.Port,
			vericonf.Email.Dialer.From,
			vericonf.Email.Dialer.Secret),
		email.WithToDom(vericonf.Email.Dialer.Todom),
		email.WithSubject(vericonf.Email.Dialer.Subject),
	)

	if err != nil {
		logger.Panic(err.Error())
	}

	logger.Debug("Registering Redis cache for email manager.")

	c := cache.NewRedis(vericonf.Email.Redis.Host,
		vericonf.Email.Redis.Port,
		vericonf.Email.Redis.User,
		vericonf.Email.Redis.Secret,
		vericonf.Email.Redis.DB)

	em, err := email.NewEmailManager(
		email.WithCodeExp(vericonf.Email.Coderule),
		email.WithEmailDialer(dialer),
		email.WithCache(c),
		email.WithAccExp(vericonf.Email.Accrule),
		email.WithEmailTemplate(vericonf.Email.Template),
	)

	if err != nil {
		logger.Panic(err.Error())
	}

	logger.Debug("Registering public key storage.")

	c = cache.NewRedis(vericonf.Email.Redis.Host,
		vericonf.Email.Redis.Port,
		vericonf.Email.Redis.User,
		vericonf.Email.Redis.Secret,
		(vericonf.Email.Redis.DB+1)%10,
	)

	logger.Debug("Initializing the certificate authority.")

	cm, err := cert.NewCertManager(
		cert.WithPrivateKey(vericonf.Cert.Priv),
		cert.WithCertificate(vericonf.Cert.Cert),
		cert.WithCache(c),
	)

	if err != nil {
		logger.Panic(err.Error())
	}

	logger.Debug("Initializing the signing utility.")

	km, err := keyset.NewKeyManager(
		vericonf.Keyset.NR_mem,
		vericonf.Keyset.Cap,
	)

	if err != nil {
		logger.Panic(err.Error())
	}

	logger.Debug("Initializing the turnstile utility.")

	ts := turnstile.NewTurnstile(vericonf.Turnstile.Secret)

	server := verify.NewVerificationServer(
		vericonf.Verify.Host, vericonf.Verify.Port,
		em, cm, km, ts)

	logger.Info("Starting the server now.")

	server.Start()
}
