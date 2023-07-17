package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisCache struct {
	client *redis.Client
}

func NewRedis(host string, port int, user string, secret string, db int) *RedisCache {
	addr := fmt.Sprintf("%s:%d", host, port)
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Username: user,
		Password: secret,
		DB:       db,
	})
	r := RedisCache{client}
	return &r
}

func (r *RedisCache) Get(key string) (string, error) {
	cmd := r.client.Get(context.Background(), key)
	res, err := cmd.Result()

	fmt.Println(err)

	if err == redis.Nil {
		return "", &KeyError{}
	}

	if err != nil {
		return "", &InternalError{}
	}

	return res, err
}

func (r *RedisCache) Exists(keys ...string) (int, error) {
	cmd := r.client.Exists(context.Background(), keys...)
	result, err := cmd.Result()

	if err != nil {
		return -1, &InternalError{}
	}

	return int(result), nil
}

func (r *RedisCache) Set(key string, value string, expiration time.Duration) error {
	cmd := r.client.Set(context.Background(), key, value, expiration)
	err := cmd.Err()

	if err != nil && err != redis.Nil {
		return &InternalError{}
	}
	return nil
}

func (r *RedisCache) GetDel(key string) (string, error) {
	cmd := r.client.GetDel(context.Background(), key)
	res, err := cmd.Result()

	if err == redis.Nil {
		return "", &KeyError{}
	}

	if err != nil {
		return "", &InternalError{}
	}

	return res, nil
}

func (r *RedisCache) Del(key string) error {
	cmd := r.client.Del(context.Background(), key)
	res, err := cmd.Result()

	if err != nil && err != redis.Nil {
		return &InternalError{}
	}

	if res == 0 {
		return &KeyError{}
	}

	return nil
}

func (r *RedisCache) SAdd(set string, elem string) error {
	_, err := r.client.SAdd(context.Background(), set, elem).Result()
	if err != nil {
		return &InternalError{}
	}
	return nil
}

func (r *RedisCache) SIsmember(set string, elem string) (bool, error) {
	res, err := r.client.SIsMember(context.Background(), set, elem).Result()
	if err != nil {
		return false, &InternalError{}
	}
	return res, nil
}
