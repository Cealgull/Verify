package keypair

// #cgo CFLAGS: -O2 -Wall
// #cgo LDFLAGS: -lcrypto
// #include "ringsig.h"
// #include "string.h"
import "C"
import (
	"math/rand"
	"unsafe"
)

type RingKeyset struct {
	Nr_mem int
}

type RingKeyPair struct {
	Pubs   string `json:"pubs"`
	Priv   string `json:"priv"`
	Nr_mem int    `json:"nr_mem"`
	Mine   int    `json:"mine"`
}

func NewRingKeyset(nr_mem int) *RingKeyset {
	k := &RingKeyset{nr_mem}
	C.ringsig_keyset_init(C.int(nr_mem))
	return k
}

func (k *RingKeyset) Renew() {
	C.ringsig_keyset_renew(C.int(k.Nr_mem))
}

func (k *RingKeyset) Dispatch() *RingKeyPair {
	mine := rand.Intn(k.Nr_mem)
	kp := C.ringsig_keypair_dispatch(C.int(mine))
	return &RingKeyPair{Pubs: C.GoString(kp.pubs), Priv: C.GoString(kp.priv), Nr_mem: k.Nr_mem, Mine: mine}
}

func (k *RingKeyset) Verify(msg string, sig string) bool {
	cmsg := C.CString(msg)
	msglen := C.int(len(msg))
	csigb64 := C.CString(sig)
	return int(C.ringsig_verify_b64(cmsg, msglen, csigb64)) == 1
}

func RingSign(kp *RingKeyPair, msg string) string {
	cmsg := C.CString(msg)
	nr_mem := C.int(kp.Nr_mem)
	siglen := C.ulong(C.ringsig_signb64_len(nr_mem))
	csig := (*C.char)(C.calloc(1, siglen))
	spec := C.ringsig_keypair_extern_t{
		priv:   C.CString(kp.Priv),
		pubs:   C.CString(kp.Pubs),
		nr_mem: C.int(kp.Nr_mem),
		mine:   C.int(kp.Mine),
	}
	cspec := (*C.ringsig_keypair_extern_t)(unsafe.Pointer(&spec))
	C.ringsig_sign_b64(cspec, cmsg, C.int(len(msg)), csig)
	return C.GoString((*C.char)(csig))
}
