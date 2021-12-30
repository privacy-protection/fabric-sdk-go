package he

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSm4Encrypt(t *testing.T) {
	key := RandBytes(16)
	data := RandBytes(64)
	cipher, err := sm4Encrypt(key, data)
	require.NoError(t, err)
	require.NotNil(t, cipher)
}

func TestSm4Decrypt(t *testing.T) {
	key := RandBytes(16)
	data := RandBytes(64)
	fmt.Println(data)
	ciphertext, err := sm4Encrypt(key, data)
	require.NoError(t, err)
	data1, err := sm4Decrypt(key, ciphertext)
	fmt.Println(data1)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, data1))
}

func TestSm2Generate(t *testing.T) {
	key, err := sm2Generate()
	require.NoError(t, err)
	require.NotNil(t, key)
}

func TestSm2Encrypt(t *testing.T) {
	prikey, err := sm2Generate()
	require.NoError(t, err)

	pubkey := &prikey.PublicKey
	data := RandBytes(64)
	ciphertext, err := sm2Encrypt(*pubkey, data)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)
}

func TestSm2Decrypt(t *testing.T) {
	prikey, err := sm2Generate()
	require.NoError(t, err)

	pubkey := &prikey.PublicKey
	data := RandBytes(300)
	ciphertext, err := sm2Encrypt(*pubkey, data)
	require.NoError(t, err)

	data1, err := sm2Decrypt(prikey, ciphertext)
	require.True(t, bytes.Equal(data, data1))
}

func RandBytes(len int) []byte {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		b := r.Intn(26) + 65
		bytes[i] = byte(b)
	}
	return bytes
}
