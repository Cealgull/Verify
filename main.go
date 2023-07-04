package main

import (
	"github.com/Cealgull/Verify/internal/email"
	"github.com/Cealgull/Verify/internal/fabric"
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
		email.WithFrom(dialerMap["account"].(string),
			dialerMap["fromdom"].(string),
			dialerMap["secret"].(string)),
		email.WithDialerTemplate(dialerMap["template"].(string)),
		email.WithToDom(dialerMap["todom"].(string)),
		email.WithClient(dialerMap["server"].(string)))

	if err != nil {
		logger.Panic(err.Error())
	}

	redisMap := emailMap["redis"].(map[string]interface{})

	if err != nil {
		logger.Panic(err.Error())
	}

	em, err := email.NewEmailManager(
		email.WithCodeExp(emailMap["coderule"].(string)),
		email.WithRedis(redisMap["server"].(string),
			redisMap["user"].(string),
			redisMap["secret"].(string),
			redisMap["db"].(int)),
		email.WithEmailDialer(dialer),
		email.WithAccExp(emailMap["accrule"].(string)),
		email.WithEmailTemplate(emailMap["template"].(string)),
	)

	if err != nil {
		logger.Panic(err.Error())
	}

	fabricMap := viper.GetStringMapString("fabric")

	fm, err := fabric.NewFabricManager(
		fabric.WithOrg(fabricMap["org"]),
		fabric.WithCAHost(fabricMap["cahost"]),
		fabric.WithConfiguration(fabricMap["cacerts"]),
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

	serverMap := viper.GetStringMap("server")
	server := verify.New(serverMap["host"].(string), serverMap["port"].(string), em, fm, km, ts)

	server.Start()
}
