package delegate

import (
	"bytes"
	"testing"

	"github.com/hyperledger/fabric-sdk-go/pkg/crypto/fle"
	"github.com/privacy-protection/common/abe/utils"
	"github.com/stretchr/testify/require"
)

func TestKpabeUpdateThreshold(t *testing.T) {
	masterKey, err := fle.Setup(256)
	require.NoError(t, err)

	a := utils.Hash("pufa")
	b := utils.Hash("zhaoshang")
	c := utils.Hash("zhongzhai")
	d := utils.Hash("jianshe")

	key, err := fle.KeyGen(masterKey, []int{a, b, c, d})
	require.NoError(t, err)

	data := []byte("hello world")
	ciphertext, err := fle.Encrypt(data, []int{a, b}, key.Param)
	require.NoError(t, err)

	key, err = KpabeUpdateThreshold(key, []int{2, 0, 0, 0, 0})

	decodedData, err := fle.Decrypt(key, ciphertext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, decodedData))
}

func TestKpabeFieldDelegate(t *testing.T) {
	masterKey, err := fle.Setup(256)
	require.NoError(t, err)

	a := utils.Hash("pufa")
	b := utils.Hash("zhaoshang")
	c := utils.Hash("zhongzhai")
	d := utils.Hash("jianshe")

	key, err := fle.KeyGen(masterKey, []int{a, b, c, d})
	require.NoError(t, err)

	data := []byte("hello world")
	ciphertext, err := fle.Encrypt(data, []int{a, b}, key.Param)
	require.NoError(t, err)

	key, err = KpabeFieldDelegate(key, []int{a, c, d})

	decodedData, err := fle.Decrypt(key, ciphertext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, decodedData))
}
