package keypair

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/anon"
)

const (
	nr_mem = 16
)

var token_old KeyPair

func TestGenKeyPair(t *testing.T) {

	suite := edwards25519.NewBlakeSHA256Ed25519()

	pubs := make(anon.Set, nr_mem)
	priv := make([]kyber.Scalar, nr_mem)

	for i := 0; i < nr_mem; i++ {
		priv[i] = suite.Scalar().Pick(suite.RandomStream())
		pubs[i] = suite.Point().Mul(priv[i], nil)
	}

	token_old = KeyPair{
		Pubs: pubs,
		Priv: priv[0],
		Idx:  0,
	}
}

type keyPairPrimitive struct {
	Pubs string `json:"pubs"`
	Priv string `json:"priv"`
	Idx  int    `json:"idx"`
}

func TestSignKeyPairJSON(t *testing.T) {

	data, err := json.Marshal(&token_old)

	assert.Nil(t, err)

	var token_new KeyPair
	var temp KeyPair
	var token_pubs keyPairPrimitive

	err = json.Unmarshal(data, &token_new)
	assert.Nil(t, err)

	err = json.Unmarshal(data, &token_pubs)
	assert.Nil(t, err)

	token_priv := token_pubs

	token_pubs.Pubs = ";'["
	token_priv.Priv = ";'["

	data, err = json.Marshal(&token_pubs)
	assert.Nil(t, err)

	err = json.Unmarshal(data, &temp)
	assert.NotNil(t, err)

	data, err = json.Marshal(&token_priv)
	assert.Nil(t, err)

	err = json.Unmarshal(data, &temp)
	assert.NotNil(t, err)

	token_pubs.Pubs = "YWJjZAo=,"
	token_priv.Priv = "YmNkZQo="

	data, err = json.Marshal(&token_pubs)
	assert.Nil(t, err)

	err = json.Unmarshal(data, &temp)
	assert.NotNil(t, err)

	data, err = json.Marshal(&token_priv)
	assert.Nil(t, err)

	err = json.Unmarshal(data, &temp)
	assert.NotNil(t, err)

}
