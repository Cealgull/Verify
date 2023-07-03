package main

import (
	"github.com/Cealgull/Verify/internal/email"
	"github.com/Cealgull/Verify/internal/fabric"
	"github.com/Cealgull/Verify/internal/sign"
	"github.com/Cealgull/Verify/internal/verify"
	"github.com/Cealgull/Verify/pkg/turnstile"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func main() {

	logger, _ := zap.NewProduction()

	viper.AddConfigPath("/etc/cealgull-verify/config.yaml")

	err := viper.ReadInConfig()

	if err != nil {
		logger.Panic(err.Error())
	}

	dialer, err := email.NewEmailDialer("example.com", "org.com", "localhost:25", "Subject%s")

	if err != nil {
		logger.Panic(err.Error())
	}

	em, err := email.New(
		email.WithCodeExp("\\d{6}"),
		email.WithRedis("localhost", "6379", "CealgullVerify", "CealgullVerify-secret", 0),
		email.WithEmailDialer(dialer),
		email.WithAccExp("[a-zA-Z0-9-_\\.]{50}"),
	)

	if err != nil {
		logger.Panic(err.Error())
	}

	fm, err := fabric.New(
		fabric.WithOrg("Org1"),
		fabric.WithCAHost("CAOrg1.example.com"),
	)

	if err != nil {
		logger.Panic(err.Error())
	}

	sm, err := sign.NewSignManager(16, 1024)

	if err != nil {
		logger.Panic(err.Error())
	}
	ts := turnstile.NewTurnstile("dummy")

	server := verify.New("localhost", "8080", em, fm, sm, ts)
	server.Start()
}
