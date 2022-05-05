package ole

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/privacy-protection/common/abe/parser"
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

func TestUnequal(t *testing.T) {
	masterKey, err := Setup()
	require.NoError(t, err)

	data := []byte("hello world")
	ciphertext, err := Encrypt(data, "a and b and name != user1 and time > 1024", masterKey.Param)
	require.NoError(t, err)

	timeAtts, err := commonSyntax.TransferToAttributes("time = 2048", 32)
	require.NoError(t, err)

	atts1, err := commonSyntax.TransferToAttributes("name = user1", 32)
	require.NoError(t, err)
	atts1 = append(atts1, []string{"a", "b"}...)
	atts1 = append(atts1, timeAtts...)
	key1, err := KeyGen(masterKey, atts1)
	require.NoError(t, err)

	atts2, err := commonSyntax.TransferToAttributes("name = user2", 32)
	require.NoError(t, err)
	atts2 = append(atts2, []string{"a", "b"}...)
	atts2 = append(atts2, timeAtts...)
	key2, err := KeyGen(masterKey, atts2)
	require.NoError(t, err)

	atts3, err := commonSyntax.TransferToAttributes("name = user3", 32)
	require.NoError(t, err)
	atts3 = append(atts3, []string{"a", "b"}...)
	atts3 = append(atts3, timeAtts...)
	key3, err := KeyGen(masterKey, atts3)
	require.NoError(t, err)

	decodedData, err := Decrypt(key1, ciphertext)
	require.Error(t, err)

	decodedData, err = Decrypt(key2, ciphertext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, decodedData))
	fmt.Println(string(decodedData))

	decodedData, err = Decrypt(key3, ciphertext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, decodedData))
	fmt.Println(string(decodedData))
}

func TestMyParsePolicy(t *testing.T) {
	policy := "name = user1"
	bits := 8
	_, i2s, err := parser.MyParsePolicy(policy, bits)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(i2s)
}

func TestNow(t *testing.T) {
	masterKey, err := Setup()
	require.NoError(t, err)

	atts, err := commonSyntax.TransferToAttributes("time = 1751678099", 32)
	atts = append(atts, []string{"a", "b"}...)
	require.NoError(t, err)
	key, err := KeyGen(masterKey, atts)
	require.NoError(t, err)

	data := []byte("hello world")
	ciphertext, err := Encrypt(data, "((a and b) and time > 1651678086) or username_admin", key.Param)
	require.NoError(t, err)

	decodedData, err := Decrypt(key, ciphertext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, decodedData))
}
