package keypair

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	nr_mem = 16
)

var k *RingKeyset

func TestVerify(t *testing.T) {
	msg := "hello world"
	kp := k.Dispatch()
	sig := RingSign(kp, msg)
	assert.True(t, k.Verify(msg, sig))
}

func TestRenew(t *testing.T) {
	k.Renew()
}

func TestMain(m *testing.M) {
	k = NewRingKeyset(nr_mem)
	m.Run()
}
