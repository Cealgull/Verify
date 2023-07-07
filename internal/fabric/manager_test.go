package fabric

import (
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/hyperledger/fabric-sdk-go/pkg/fab/mocks"
	"github.com/hyperledger/fabric-sdk-go/pkg/msp/test/mockmsp"
	"github.com/stretchr/testify/assert"
)

var mgr *FabricManager
var server *mockmsp.MockFabricCAServer
var suite *mocks.MockCryptoSuite

func TestStartCAServer(t *testing.T) {
	suite = &mocks.MockCryptoSuite{}
	server = &mockmsp.MockFabricCAServer{}
	lis, err := net.Listen("tcp", "localhost:2333")

	assert.Nil(t, err)
	server.Start(lis, suite)
}

func TestFabricManager(t *testing.T) {

	var err error

	_, err = NewFabricManager(
		WithConfiguration("./testdata/ccp_notfound.yaml"),
	)

	assert.NotNil(t, err)

	_, err = NewFabricManager(
		WithConfiguration("./testdata/ccp_mock.yaml"),
		WithOrg("Org2"),
		WithCAHost("ca.org1.example.com"),
	)

	assert.NotNil(t, err)

	mgr, err = NewFabricManager(
		WithConfiguration("./testdata/ccp_mock.yaml"),
		WithOrg("Org1"),
		WithCAHost("ca.org1.example.com"),
	)

	assert.Nil(t, err)

}

func TestFabricManagerRegister(t *testing.T) {
	k := rand.Int63()

	err := mgr.Register(fmt.Sprintf("user%d", k), fmt.Sprintf("%d", k))
	if err != nil {
		panic(err)
	}
}
