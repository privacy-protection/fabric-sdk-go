package delegate

import (
	"bytes"
	"testing"

	"github.com/hyperledger/fabric-sdk-go/pkg/crypto/ole"
	"github.com/privacy-protection/common/abe/utils"
	"github.com/stretchr/testify/require"
)

func TestCpabeDelegate(t *testing.T) {
	masterKey, err := ole.Setup()
	require.NoError(t, err)

	key, err := ole.KeyGen(masterKey, []string{"pufa", "zhaoshang", "zhongzhai"})
	require.NoError(t, err)

	data := []byte("hello world")
	ciphertext, err := ole.Encrypt(data, "(pufa or zhongzhai) and zhaoshang", key.Param)
	require.NoError(t, err)

	key, err = CpabeDelegate(key, []int{utils.Hash("pufa"), utils.Hash("zhaoshang")})
	decodedData, err := ole.Decrypt(key, ciphertext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, decodedData))
}

func TestInvalidCpabeDelegate(t *testing.T) {
	masterKey, err := ole.Setup()
	require.NoError(t, err)

	key, err := ole.KeyGen(masterKey, []string{"pufa", "zhaoshang", "zhongzhai"})
	require.NoError(t, err)

	data := []byte("hello world")
	ciphertext, err := ole.Encrypt(data, "(pufa or zhongzhai) and zhaoshang", key.Param)
	require.NoError(t, err)

	a := utils.Hash("pufa")
	b := utils.Hash("zhongzhai")
	key, err = CpabeDelegate(key, []int{a, b})
	_, err = ole.Decrypt(key, ciphertext)
	require.Error(t, err)
}
