package mock

import (
	"time"

	"github.com/Cealgull/Verify/internal/cache"
)

type MockCache struct {
	m      map[string]string
	geterr map[string]error
	seterr map[string]error
	delerr map[string]error
}

func NewMockCache() *MockCache {
	return &MockCache{make(map[string]string), make(map[string]error), make(map[string]error), make(map[string]error)}
}

func (r *MockCache) AddGetErr(key string, err error) {
	r.geterr[key] = err
}

func (r *MockCache) AddSetErr(key string, err error) {
	r.seterr[key] = err
}

func (r *MockCache) AddDelErr(key string, err error) {
	r.delerr[key] = err
}

func (r *MockCache) Get(key string) (string, error) {
	if err, f := r.geterr[key]; f {
		return "", err
	}
	if _, f := r.m[key]; !f {
		return "", &cache.KeyError{}
	}
	return r.m[key], nil
}

func (r *MockCache) Set(key string, value string, expiration time.Duration) error {
	if err, f := r.seterr[key]; f {
		return err
	}
	r.m[key] = value
	return nil
}

func (r *MockCache) Exists(ks ...string) (int, error) {
	cnt := 0
	for _, k := range ks {
		if err, f := r.geterr[k]; f {
			return -1, err
		}
		if _, f := r.m[k]; f {
			cnt += 1
		}
	}
	return cnt, nil
}

func (r *MockCache) GetDel(key string) (string, error) {
	if err, f := r.geterr[key]; f {
		return "", err
	}
	res := r.m[key]
	delete(r.m, key)
	return res, nil
}

func (r *MockCache) Del(key string) error {
	if err, f := r.delerr[key]; f {
		return err
	}
	if _, f := r.m[key]; !f {
		return &cache.KeyError{}
	}
	delete(r.m, key)
	return nil
}
