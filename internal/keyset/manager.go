package keyset

import (
	"encoding/base64"
	"math/rand"
	"sync"

	"github.com/Cealgull/Verify/internal/proto"
	"github.com/Cealgull/Verify/pkg/keypair"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/anon"
)

type KeyManager struct {
	suite  anon.Suite
	pubs   anon.Set
	priv   []kyber.Scalar
	nr_mem int
	cnt    int
	mtx    sync.Mutex
	cap    int
}

func NewKeyManager(nr_mem int, cap int) (*KeyManager, error) {

	suite := edwards25519.NewBlakeSHA256Ed25519()

	m := &KeyManager{
		suite:  suite,
		pubs:   nil,
		priv:   nil,
		nr_mem: nr_mem,
		cnt:    0,
		mtx:    sync.Mutex{},
		cap:    cap,
	}

	m.renewKeySet()

	return m, nil
}

func (m *KeyManager) renewKeySet() {

	pubs := make(anon.Set, m.nr_mem)
	priv := make([]kyber.Scalar, m.nr_mem)

	for i := 0; i < m.nr_mem; i++ {
		priv[i] = m.suite.Scalar().Pick(m.suite.RandomStream())
		pubs[i] = m.suite.Point().Mul(priv[i], nil)
	}

	m.pubs = pubs
	m.priv = priv
	m.cnt = 0

}

func (m *KeyManager) Verify(msg string, sigb64 string) (bool, proto.VerifyError) {

	sig, err := base64.StdEncoding.DecodeString(sigb64)

	if err != nil {
		return false, &SignatureDecodeError{}
	}

	m.mtx.Lock()

	_, err = anon.Verify(m.suite, []byte(msg), m.pubs, nil, sig)
	m.cnt += 1

	if m.cnt == m.cap {
		m.renewKeySet()
	}

	m.mtx.Unlock()

	if err != nil {
		return false, &SignatureVerificationError{}
	}

	return true, nil
}

func (m *KeyManager) Dispatch() *keypair.KeyPair {

	m.mtx.Lock()

	pubs := make(anon.Set, m.nr_mem)
	idx := rand.Int() % m.nr_mem
	copy(pubs, m.pubs)

	t := keypair.KeyPair{
		Pubs: pubs,
		Priv: m.priv[idx],
		Idx:  idx,
	}

	m.mtx.Unlock()

	return &t
}
