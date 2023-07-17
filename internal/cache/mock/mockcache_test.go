package mock

import (
	"testing"
	"time"

	"github.com/Cealgull/Verify/internal/cache"
	"github.com/stretchr/testify/assert"
)

var c *MockCache

func TestNewMockCache(t *testing.T) {
	c = NewMockCache()
}

func TestMockSimpleKV(t *testing.T) {

	err := c.Set("k1", "v1", time.Duration(1))
	assert.Nil(t, err)
	_, err = c.Get("k1")
	assert.Nil(t, err)
	_, err = c.Exists("k1")
	assert.Nil(t, err)
	_, err = c.GetDel("k1")
	assert.Nil(t, err)
	err = c.Set("k1", "v1", time.Duration(1))
	assert.Nil(t, err)
	err = c.Del("k1")
	assert.Nil(t, err)
	err = c.Del("k1")
	assert.NotNil(t, err)
	c.AddDelErr("k1", &cache.InternalError{})
	err = c.Del("k1")
	assert.NotNil(t, err)

	_, err = c.Get("k2")
	assert.NotNil(t, err)
	c.AddGetErr("k1", &cache.InternalError{})
	_, err = c.Get("k1")
	assert.NotNil(t, err)
	_, err = c.GetDel("k1")
	assert.NotNil(t, err)
	_, err = c.Exists("k1")
	assert.NotNil(t, err)
	c.AddSetErr("k1", err)
	err = c.Set("k1", "v1", time.Duration(1))
	assert.NotNil(t, err)

}

func TestMockSet(t *testing.T) {
	err := c.SAdd("s1", "k1")
	assert.Nil(t, err)
	err = c.SAdd("s1", "k2")
	assert.Nil(t, err)
	valid, err := c.SIsmember("s1", "k1")
	assert.True(t, valid)
	assert.Nil(t, err)

	valid, err = c.SIsmember("s2", "k4")
	assert.False(t, valid)
	assert.NotNil(t, err)

	valid, err = c.SIsmember("s1", "k4")
	assert.False(t, valid)
	assert.Nil(t, err)

	c.AddSetsErr("s1", &cache.InternalError{})
	err = c.SAdd("s1", "k3")
	assert.NotNil(t, err)
	valid, err = c.SIsmember("s1", "k3")
	assert.False(t, valid)
	assert.NotNil(t, err)
	c.DelSetsErr("s1")
	err = c.SAdd("s1", "k3")
	assert.Nil(t, err)
}
