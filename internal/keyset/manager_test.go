package keyset

import (
	"encoding/base64"
	"testing"

	"github.com/Cealgull/Verify/pkg/keypair"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/anon"
)

var mgr *KeyManager
var kp *keypair.KeyPair

func TestNewKeyManager(t *testing.T) {

	mgr, _ = NewKeyManager(16, 16)

	assert.Equal(t, 16, mgr.cap)
	assert.Equal(t, 16, mgr.nr_mem)
	assert.Equal(t, 0, mgr.cnt)
}

func TestDispatch(t *testing.T) {
	kp = mgr.Dispatch()
}

func TestVerify(t *testing.T) {
	msg1 := "hello world"
	msg2 := "goodbye world"

	sig := anon.Sign(edwards25519.NewBlakeSHA256Ed25519(), []byte(msg1), kp.Pubs, nil, kp.Idx, kp.Priv)
	sigb64 := base64.StdEncoding.EncodeToString(sig)

	test, _ := mgr.Verify(msg1, sigb64)

	assert.True(t, test)
	assert.Equal(t, 1, mgr.cnt)

	test, _ = mgr.Verify(msg2, sigb64)
	assert.False(t, test)

	mgr.cnt = 15
	test, _ = mgr.Verify(msg1, sigb64)
	assert.True(t, test)
	assert.Equal(t, 0, mgr.cnt)

}

func TestRenew(t *testing.T) {
	mgr.renewKeySet()
	assert.Equal(t, 0, mgr.cnt)
}
