package sign

import (
	"math/rand"
	"sync"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/anon"
)

type SignManager struct {
	suite  anon.Suite
	pubs   anon.Set
	priv   []kyber.Scalar
	nr_mem int
	cnt    int
	mtx    sync.Mutex
	cap    int
}

type SignToken struct {
	pubs anon.Set
	priv kyber.Scalar
	idx  int
}

func NewSignManager(nr_mem int, cap int) (*SignManager, error) {

	suite := edwards25519.NewBlakeSHA256Ed25519()

	m := &SignManager{
		suite:  suite,
		pubs:   nil,
		priv:   nil,
		nr_mem: nr_mem,
		cnt:    0,
		mtx:    sync.Mutex{},
		cap:    cap,
	}

	m.renew()

	return m, nil
}

func (m *SignManager) renew() {

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

func (m *SignManager) Verify(msg []byte, sig []byte) (bool, error) {

	m.mtx.Lock()
	tag, err := anon.Verify(m.suite, msg, m.pubs, nil, sig)
	m.cnt += 1
	if m.cnt == m.cap {
		m.renew()
	}
	m.mtx.Unlock()

	if err != nil {
		return false, err
	}

	if tag != nil {
		return false, nil
	}

	return true, nil
}

func (m *SignManager) Dispatch() SignToken {

	m.mtx.Lock()

	pubs := make(anon.Set, m.nr_mem)
	idx := rand.Int() % m.nr_mem
	copy(pubs, m.pubs)

	t := SignToken{
		pubs: pubs,
		priv: m.priv[idx],
		idx:  idx,
	}

	m.mtx.Unlock()

	return t
}
