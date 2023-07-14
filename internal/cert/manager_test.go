package cert

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadPem(t *testing.T) {
	b, err := loadPemFromDisk("./notexists", CERT)
	assert.Nil(t, b)
	assert.Error(t, err)

	b, err = loadPemFromDisk("./testdata/priv.pem", PRIVATE)
	assert.NotNil(t, b)
	assert.NoError(t, err)

	b, err = loadPemFromDisk("./testdata/priv.pem", CERT)
	assert.Nil(t, b)
	assert.Error(t, err)
}
