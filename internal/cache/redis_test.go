package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

var normalCache *RedisCache
var incorrectCache *RedisCache
var mock redismock.ClientMock

func TestNewRedisClient(t *testing.T) {
	var client *redis.Client
	client, mock = redismock.NewClientMock()

	normalCache = &RedisCache{client}
	incorrectCache = NewRedis("localhost:0", "", "", 0)
}

func TestSet(t *testing.T) {
	mock.ExpectSet("foo", "bar", time.Duration(5)*time.Hour).RedisNil()
	err := normalCache.Set("foo", "bar", time.Duration(5)*time.Hour)
	assert.Nil(t, err)

	err = incorrectCache.Set("foo", "bar", time.Duration(5)*time.Hour)
	assert.IsType(t, &InternalError{}, err)
}

func TestGet(t *testing.T) {

	mock.ExpectGet("user1").SetVal("code1")
	res, err := normalCache.Get("user1")
	assert.Nil(t, err)
	assert.Equal(t, "code1", res)

	mock.ExpectGet("user2").RedisNil()
	_, err = normalCache.Get("user2")
	assert.IsType(t, &KeyError{}, err)
	fmt.Println(err.Error())

	_, err = incorrectCache.Get("user1")
	assert.IsType(t, &InternalError{}, err)
	fmt.Println(err.Error())

	mock.ExpectGetDel("user1").SetVal("code1")
	res, err = normalCache.GetDel("user1")
	assert.Nil(t, err)
	assert.Equal(t, "code1", res)

	mock.ExpectGetDel("user2").RedisNil()
	_, err = normalCache.GetDel("user2")
	assert.IsType(t, &KeyError{}, err)

	_, err = incorrectCache.GetDel("user1")
	assert.IsType(t, &InternalError{}, err)

}

func TestExists(t *testing.T) {
	mock.ExpectExists("123", "234", "345").SetVal(3)
	res, err := normalCache.Exists("123", "234", "345")

	assert.Nil(t, err)
	assert.Equal(t, 3, res)

	_, err = incorrectCache.Exists("123")
	assert.IsType(t, &InternalError{}, err)
}
