package cache

import (
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
	incorrectCache = NewRedis("localhost", 0, "", "", 0)
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

	_, err = incorrectCache.Get("user1")
	assert.IsType(t, &InternalError{}, err)

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

func TestDel(t *testing.T) {
	mock.ExpectDel("123").SetVal(1)
	err := normalCache.Del("123")
	assert.Nil(t, err)
	mock.ExpectDel("123").SetVal(0)
	err = normalCache.Del("123")
	assert.IsType(t, &KeyError{}, err)
	var _ = err.Error()
	err = incorrectCache.Del("123")
	assert.IsType(t, &InternalError{}, err)
	var _ = err.Error()
}

func TestSAdd(t *testing.T) {
	mock.ExpectSAdd("pub", "123").SetVal(1)
	err := normalCache.SAdd("pub", "123")
	assert.Nil(t, err)

	err = incorrectCache.SAdd("pub", "123")
	assert.NotNil(t, err)
}

func TestSIsmember(t *testing.T) {
	mock.ExpectSIsMember("pub", "123").SetVal(true)
	valid, err := normalCache.SIsmember("pub", "123")
	assert.True(t, valid)
	assert.Nil(t, err)

	valid, err = incorrectCache.SIsmember("pub", "123")
	assert.False(t, valid)
	assert.NotNil(t, err)
}
