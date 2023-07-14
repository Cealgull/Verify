package cache

import "time"

type Cache interface {
	Get(key string) (string, error)
	Exists(key ...string) (int, error)
	Del(key string) error
	Set(key string, value string, expiration time.Duration) error
	GetDel(key string) (string, error)
	SAdd(set string, elem string) error
	SIsmember(set string, elem string) (bool, error)
}
