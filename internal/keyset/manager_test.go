package keyset

import (
	"testing"

	"github.com/Cealgull/Verify/pkg/keypair"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

var mgr *KeyManager

func TestNewKeyManager(t *testing.T) {
	assert.Equal(t, 16, mgr.cap)
	assert.Equal(t, 16, mgr.keyset.Nr_mem)
	assert.Equal(t, 0, mgr.cnt)
}

func TestRenewKeySet(t *testing.T) {
	mgr.renewKeySet()
	assert.Equal(t, 0, mgr.cnt)
}

func TestSign(t *testing.T) {

	msg := "hello world"

	kp := mgr.Dispatch()
	sig := keypair.RingSign(kp, msg)

	ok, err := mgr.Verify(msg, "[?/]")
	assert.False(t, ok)
	assert.IsType(t, &SignatureDecodeError{}, err)

	var _ = err.Status()
	var _ = err.Message()

	mgr.cnt = 15
	ok, err = mgr.Verify(msg, sig)
	assert.True(t, ok)
	assert.NoError(t, err)

	ok, err = mgr.Verify("[?/]", sig)
	assert.False(t, ok)
	assert.IsType(t, &SignatureVerificationError{}, err)

	var _ = err.Status()
	var _ = err.Message()

}

func TestMain(m *testing.M) {

	l, _ := zap.NewProduction()
	mgr, _ = NewKeyManager(l.Sugar(), 16, 16)

	m.Run()
}
