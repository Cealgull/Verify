package mock

import (
	"time"

	"github.com/Cealgull/Verify/internal/cache"
)

type MockCache struct {
	m       map[string]string
	sets    map[string]map[string]bool
	geterr  map[string]error
	seterr  map[string]error
	setserr map[string]error
	delerr  map[string]error
}

func NewMockCache() *MockCache {
	return &MockCache{
		m:       make(map[string]string),
		sets:    make(map[string]map[string]bool),
		geterr:  make(map[string]error),
		seterr:  make(map[string]error),
		setserr: make(map[string]error),
		delerr:  make(map[string]error)}
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

func (r *MockCache) AddSetsErr(key string, err error) {
	r.setserr[key] = err
}

func (r *MockCache) DelSetsErr(key string) {
	delete(r.setserr, key)
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

func (r *MockCache) SAdd(set string, key string) error {
	if err, f := r.setserr[set]; f {
		return err
	}
	if s, f := r.sets[set]; f {
		s[key] = true
	} else {
		s = make(map[string]bool)
		s[key] = true
		r.sets[set] = s
	}
	return nil
}

func (r *MockCache) SIsmember(set string, key string) (bool, error) {
	if err, f := r.setserr[set]; f {
		return false, err
	}

	if _, f := r.sets[set]; !f {
		return false, &cache.KeyError{}
	}

	_, f := r.sets[set][key]

	return f, nil
}
