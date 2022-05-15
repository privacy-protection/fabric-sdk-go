package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/privacy-protection/hybrid-encryption/third_party/github.com/hyperledger/fabric/bccsp"
	"github.com/privacy-protection/hybrid-encryption/third_party/github.com/hyperledger/fabric/bccsp/factory"
	"github.com/privacy-protection/hybrid-encryption/third_party/github.com/hyperledger/fabric/bccsp/sw"

	"github.com/privacy-protection/hybrid-encryption/third_party/github.com/hyperledger/fabric/bccsp/utils"
)

// Ciphertext contains the data generate by hybrid encryption
type Ciphertext struct {
	// The ciphertext encrypted by symmetric encryption
	Ciphertext []byte `json:"ciphertext"`
	// The encrypted symmetric keys using asymmetric encryption
	Keys map[string][]byte `json:"keys"`
}

// Identity represents the identity of user
type Identity struct {
	// The unique identity
	ID string
	// The certificate content or the certificate path
	Cert string
	// The private key content or the private key path
	Key string
}

// Encrypt the data
func Encrypt(data []byte, users []*Identity) ([]byte, error) {
	csp, err := getDefaultBCCSP()
	if err != nil {
		return nil, fmt.Errorf("get bccsp error, %v", err)
	}
	result := &Ciphertext{Keys: make(map[string][]byte)}
	// Random the aes key
	key, err := sw.GetRandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("get random bytes error, %v", err)
	}
	// Encrypt the data by symmetric encryption
	k, err := csp.KeyImport(key, &bccsp.AES256ImportKeyOpts{Temporary: true})
	if err != nil {
		return nil, fmt.Errorf("bccsp key import error, %v", err)
	}
	result.Ciphertext, err = csp.Encrypt(k, data, &bccsp.AESCBCPKCS7ModeOpts{})
	if err != nil {
		return nil, fmt.Errorf("bccsp encrypt error, %v", err)
	}
	// Encrypt the key by asymmetric encryption
	for _, user := range users {
		// Get the public key from certificate
		pk, err := user.GetPublicKey(csp)
		if err != nil {
			return nil, fmt.Errorf("get public key error, %v", err)
		}
		// Encrypt the key
		ciphertext, err := csp.Encrypt(pk, key, nil)
		if err != nil {
			return nil, fmt.Errorf("bccsp encrypt error, %v", err)
		}
		// Put it into the result
		result.Keys[user.ID] = ciphertext
	}
	// Marshal the result
	return json.Marshal(result)
}

// Decrypt the ciphertext
func Decrypt(ciphertext []byte, user *Identity) ([]byte, error) {
	csp, err := getDefaultBCCSP()
	if err != nil {
		return nil, fmt.Errorf("get bccsp error, %v", err)
	}
	c := &Ciphertext{}
	// Unmarshal
	if err := json.Unmarshal(ciphertext, c); err != nil {
		return nil, fmt.Errorf("unmarshal Ciphertext error, %v", err)
	}
	// Get the private key
	sk, err := user.GetPrivateKey(csp)
	if err != nil {
		return nil, fmt.Errorf("get private key error, %v", err)
	}
	// Decrypt the key by asymmetric decryption
	var key []byte
	if encryptedKey, ok := c.Keys[user.ID]; ok {
		key, err = csp.Decrypt(sk, encryptedKey, nil)
		if err != nil {
			return nil, fmt.Errorf("bccsp decrypt error, %v", err)
		}
	} else {
		return nil, fmt.Errorf("could not decrypt by user [%s]", user.ID)
	}
	// Load the symmetric key
	k, err := csp.KeyImport(key, &bccsp.AES256ImportKeyOpts{Temporary: true})
	if err != nil {
		return nil, fmt.Errorf("bccsp key import error, %v", err)
	}
	// Decrypt the data by symmetric decryption
	return csp.Decrypt(k, c.Ciphertext, &bccsp.AESCBCPKCS7ModeOpts{})
}

func getDefaultBCCSP() (bccsp.BCCSP, error) {
	f := &factory.SWFactory{}
	return f.Get(&factory.FactoryOpts{
		ProviderName: "SW",
		SwOpts: &factory.SwOpts{
			HashFamily: "SHA2",
			SecLevel:   256,
		},
	})
}

// GetPublicKey returns the public key
func (i *Identity) GetPublicKey(csp bccsp.BCCSP) (bccsp.Key, error) {
	var b []byte
	var err error
	if _, err = os.Stat(i.Cert); err == nil {
		b, err = ioutil.ReadFile(i.Cert)
		if err != nil {
			return nil, fmt.Errorf("read file error, %v", err)
		}
	} else {
		b = []byte(i.Cert)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("pem decode error")
	}
	x509Cert, err := utils.DERToX509Certificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate error, %v", err)
	}
	return csp.KeyImport(x509Cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
}

// GetPrivateKey returns the private key
func (i *Identity) GetPrivateKey(csp bccsp.BCCSP) (bccsp.Key, error) {
	var b []byte
	var err error
	if _, err = os.Stat(i.Key); err == nil {
		b, err = ioutil.ReadFile(i.Key)
		if err != nil {
			return nil, fmt.Errorf("read file error, %v", err)
		}
	} else {
		b = []byte(i.Key)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("pem decode error")
	}
	return csp.KeyImport(block.Bytes, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: true})
}
