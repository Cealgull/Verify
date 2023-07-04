package fabric

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/spf13/viper"
)

var mgr *FabricManager

func TestFabricManager(t *testing.T) {

	viper.AddConfigPath("../../configs")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	err := viper.ReadInConfig()

	if err != nil {
		panic(err)
	}

	fabricMap := viper.GetStringMapString("fabric")

	if err != nil {
		panic(err)
	}

	mgr, err = NewFabricManager(
		WithConfiguration("../../configs/ccp.yaml"),
		WithOrg("Org1"),
		WithCAHost(fabricMap["cahost"]),
	)

	if err != nil {
		panic(err)
	}

}

func TestFabricManagerRegister(t *testing.T) {
	k := rand.Int63()

	err := mgr.Register(fmt.Sprintf("user%d", k), fmt.Sprintf("%d", k))
	if err != nil {
		panic(err)
	}
}
