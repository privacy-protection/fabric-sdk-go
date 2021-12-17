package fle

import (
	"bytes"
	"testing"

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

	key, err := KeyGen(masterKey, []int{1, 2, 3, 4})
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestEncrypt(t *testing.T) {
	masterKey, err := Setup()
	require.NoError(t, err)

	key, err := KeyGen(masterKey, []int{1, 2, 3, 4})
	require.NoError(t, err)

	data := []byte("hello world")
	ciphertext, err := Encrypt(data, []int{2}, key.Param)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)
}

func TestDecrypt(t *testing.T) {
	masterKey, err := Setup()
	require.NoError(t, err)

	key, err := KeyGen(masterKey, []int{1, 2, 3, 4})
	require.NoError(t, err)

	data := []byte("hello world")
	ciphertext, err := Encrypt(data, []int{2}, key.Param)
	require.NoError(t, err)

	decodedData, err := Decrypt(key, ciphertext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, decodedData))
}

func TestInvalidDecrypt(t *testing.T) {
	masterKey, err := Setup()
	require.NoError(t, err)

	key, err := KeyGen(masterKey, []int{1, 2, 3, 4})
	require.NoError(t, err)

	data := []byte("hello world")
	ciphertext, err := Encrypt(data, []int{0}, key.Param)
	require.NoError(t, err)

	_, err = Decrypt(key, ciphertext)
	require.Error(t, err)
}
