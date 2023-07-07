package cache

import "time"

type KeyError struct{}

func (e *KeyError) Error() string {
	return "Cache: Key Not Found"
}

type InternalError struct{}

func (e *InternalError) Error() string {
	return "Cache: Internal Connection Error"
}

type Cache interface {
	Get(key string) (string, error)
	Exists(key ...string) (int, error)
	Set(key string, value string, expiration time.Duration) error
	GetDel(key string) (string, error)
}
