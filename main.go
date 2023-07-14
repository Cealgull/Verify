package main

import (
	"fmt"

	"github.com/Cealgull/Verify/internal/cache"
	"github.com/Cealgull/Verify/internal/cert"
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

	emailMap := viper.GetStringMap("email")
	dialerMap := emailMap["dialer"].(map[string]interface{})

	dialer, err := email.NewEmailDialer(
		email.WithClient(dialerMap["host"].(string),
			dialerMap["port"].(int),
			dialerMap["from"].(string),
			dialerMap["secret"].(string)),
		email.WithToDom(dialerMap["todom"].(string)),
		email.WithSubject(dialerMap["subject"].(string)),
	)

	if err != nil {
		logger.Panic(err.Error())
	}

	redisMap := emailMap["redis"].(map[string]interface{})

	if err != nil {
		logger.Panic(err.Error())
	}

	c := cache.NewRedis(redisMap["server"].(string),
		redisMap["user"].(string),
		redisMap["secret"].(string),
		redisMap["db"].(int))

	em, err := email.NewEmailManager(
		email.WithCodeExp(emailMap["coderule"].(string)),
		email.WithEmailDialer(dialer),
		email.WithCache(c),
		email.WithAccExp(emailMap["accrule"].(string)),
		email.WithEmailTemplate(emailMap["template"].(string)),
	)
	if err != nil {
		logger.Panic(err.Error())
	}

	certMap := viper.GetStringMap("cert")

	c = cache.NewRedis(redisMap["server"].(string),
		redisMap["user"].(string),
		redisMap["secret"].(string),
		redisMap["db"].(int)+1)

	cm, err := cert.NewCertManager(
		cert.WithPrivateKey(certMap["priv"].(string)),
		cert.WithCertificate(certMap["cert"].(string)),
		cert.WithCache(c),
	)

	if err != nil {
		logger.Panic(err.Error())
	}

	keyMap := viper.GetStringMap("keyset")
	km, err := keyset.NewKeyManager(keyMap["nr_mem"].(int),
		keyMap["cap"].(int))

	if err != nil {
		logger.Panic(err.Error())
	}

	turnstileMap := viper.GetStringMapString("turnstile")
	ts := turnstile.NewTurnstile(turnstileMap["secret"])

	verifyMap := viper.GetStringMap("verify")
	server := verify.NewVerificationServer(
		fmt.Sprintf("%s:%d",
			verifyMap["host"].(string),
			verifyMap["port"].(int)),
		em, cm, km, ts)

	server.Start()
}
