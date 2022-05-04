package ole

import (
	"bytes"
	"testing"

	commonSyntax "github.com/privacy-protection/common/abe/parser/syntax"
	"github.com/stretchr/testify/require"
)

func TestSetup(t *testing.T) {
	masterKey, err := Setup()
	require.NoError(t, err)
	require.NotNil(t, masterKey)
}

func TestKeyGen(t *testing.T) {
	masterKey, err := Setup()
	require.NoError(t, err)

	key, err := KeyGen(masterKey, []string{"pufa", "zhaoshang"})
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestEncrypt(t *testing.T) {
	masterKey, err := Setup()
	require.NoError(t, err)

	key, err := KeyGen(masterKey, []string{"pufa", "zhaoshang"})
	require.NoError(t, err)

	data := []byte("hello world")
	ciphertext, err := Encrypt(data, "(pufa or jiaohang) and zhaoshang", key.Param)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)
}

func TestDecrypt(t *testing.T) {
	masterKey, err := Setup()
	require.NoError(t, err)

	key, err := KeyGen(masterKey, []string{"pufa", "zhaoshang"})
	require.NoError(t, err)

	data := []byte("hello world")
	ciphertext, err := Encrypt(data, "(pufa or zhongzhai) and zhaoshang", key.Param)
	require.NoError(t, err)

	decodedData, err := Decrypt(key, ciphertext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, decodedData))
}

func TestInvalidDecrypt(t *testing.T) {
	masterKey, err := Setup()
	require.NoError(t, err)

	key, err := KeyGen(masterKey, []string{"pufa", "zhaoshang"})
	require.NoError(t, err)

	data := []byte("hello world")
	ciphertext, err := Encrypt(data, "(pufa and zhaoshang and jiaohang) or zhongzhai", key.Param)
	require.NoError(t, err)

	_, err = Decrypt(key, ciphertext)
	require.Error(t, err)
}

func TestNumberUnequal(t *testing.T) {
	masterKey, err := Setup()
	require.NoError(t, err)

	data := []byte("hello world")
	ciphertext, err := Encrypt(data, "name != user1", masterKey.Param)
	require.NoError(t, err)

	atts1, err := commonSyntax.TransferToAttributes("name = user1", 32)
	require.NoError(t, err)
	key1, err := KeyGen(masterKey, atts1)
	require.NoError(t, err)

	atts2, err := commonSyntax.TransferToAttributes("name = user2", 32)
	require.NoError(t, err)
	key2, err := KeyGen(masterKey, atts2)
	require.NoError(t, err)

	decodedData, err := Decrypt(key1, ciphertext)
	require.Error(t, err)

	decodedData, err = Decrypt(key2, ciphertext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, decodedData))
}
