package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHybridEncryption(t *testing.T) {
	data := []byte("test")
	adminOrg1 := &Identity{
		ID:   "Admin@org1.example.com",
		Key:  filepath.Join("testdata", "Admin@org1.example.com_sk"),
		Cert: filepath.Join("testdata", "Admin@org1.example.com-cert.pem"),
	}
	adminOrg2 := &Identity{
		ID:   "Admin@org2.example.com",
		Key:  filepath.Join("testdata", "Admin@org2.example.com_sk"),
		Cert: filepath.Join("testdata", "Admin@org2.example.com-cert.pem"),
	}
	user1Org1 := &Identity{
		ID:   "User1@org1.example.com",
		Key:  filepath.Join("testdata", "User1@org1.example.com_sk"),
		Cert: filepath.Join("testdata", "User1@org1.example.com-cert.pem"),
	}
	ciphertext, err := Encrypt(data, []*Identity{adminOrg1, user1Org1})
	require.NoError(t, err)
	fmt.Println(string(ciphertext))

	decryptData, err := Decrypt(ciphertext, adminOrg1)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, decryptData))

	decryptData, err = Decrypt(ciphertext, user1Org1)
	require.NoError(t, err)
	require.True(t, bytes.Equal(data, decryptData))

	decryptData, err = Decrypt(ciphertext, adminOrg2)
	require.Error(t, err)
}
