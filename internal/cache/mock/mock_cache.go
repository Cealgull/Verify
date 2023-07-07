package mock

import (
	"time"
)

type MockCache struct {
	m map[string]string
}

func NewMockRedisCache() *MockCache {
	return &MockCache{make(map[string]string)}
}

func (r *MockCache) Get(key string) (string, error) {
	return r.m[key], nil
}

func (r *MockCache) Set(key string, value string, expiration time.Duration) error {
	r.m[key] = value
	return nil
}

func (r *MockCache) GetDel(key string) (string, error) {
	res := r.m[key]
	delete(r.m, key)
	return res, nil
}
