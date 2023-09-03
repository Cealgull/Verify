package keyset

import (
	"encoding/base64"
	"sync"

	"github.com/Cealgull/Verify/internal/proto"
	"github.com/Cealgull/Verify/pkg/keypair"
	"go.uber.org/zap"
)

type KeyManager struct {
	logger *zap.SugaredLogger
	keyset *keypair.RingKeyset
	cnt    int
	cap    int
	mtx    sync.Mutex
}

func NewKeyManager(logger *zap.SugaredLogger, nr_mem int, cap int) (*KeyManager, error) {

	m := &KeyManager{
		logger: logger,
		keyset: keypair.NewRingKeyset(nr_mem),
		cnt:    0,
		mtx:    sync.Mutex{},
		cap:    cap,
	}

	m.renewKeySet()

	return m, nil
}

func (m *KeyManager) renewKeySet() {

	m.logger.Info("Renewing the current ring keyset.")
	m.keyset.Renew()
	m.cnt = 0
}

func (m *KeyManager) Verify(msg string, sigb64 string) (bool, proto.VerifyError) {

	_, err := base64.StdEncoding.DecodeString(sigb64)

	if err != nil {
		m.logger.Debugf("Base64 decoding error for signature: %s.", sigb64)
		return false, &SignatureDecodeError{}
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	ok := m.keyset.Verify(msg, sigb64)

	m.cnt += 1

	if m.cnt == m.cap {
		m.logger.Infof("Verification hit the capacity. Try renewing the ring keyset.")
		m.renewKeySet()
	}

	if !ok {
		m.logger.Debugf("Signature verification failed for %s.", sigb64)
		return false, &SignatureVerificationError{}
	}

	m.logger.Debugf("Ring singature verfication success for %s.", sigb64)
	return true, nil
}

func (m *KeyManager) Dispatch() *keypair.RingKeyPair {

	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.logger.Infof("Dispatching new ring keypair now.")

	return m.keyset.Dispatch()
}
