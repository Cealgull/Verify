package keypair

import (
	"encoding/json"
	"testing"

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

func TestSignKeyPairJSON(t *testing.T) {

	data, err := json.Marshal(&token_old)
	if err != nil {
		panic(err)
	}
	var token_new KeyPair

	err = json.Unmarshal(data, &token_new)
	if err != nil {
		panic(err)
	}
}
