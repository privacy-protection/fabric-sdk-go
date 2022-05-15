package sm4

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// GetRandomBytes returns len random looking bytes
func GetRandomBytes(len int) ([]byte, error) {
	if len < 0 {
		return nil, errors.New("Len must be larger than 0")
	}

	buffer := make([]byte, len)

	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
	}

	return buffer, nil
}

func pkcs7Padding(src []byte) []byte {
	padding := BlockSize - len(src)%BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > sm4.BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

func sm4CBCEncrypt(key, s []byte) ([]byte, error) {
	return sm4CBCEncryptWithRand(rand.Reader, key, s)
}

func sm4CBCEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	if len(s)%BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, BlockSize+len(s))
	iv := ciphertext[:BlockSize]
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[BlockSize:], s)

	return ciphertext, nil
}

func sm4CBCDecrypt(key, src []byte) ([]byte, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(src) < BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}
	iv := src[:BlockSize]
	src = src[BlockSize:]

	if len(src)%BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(src, src)

	return src, nil
}

// SM4CBCPKCS7Encrypt combines CBC encryption and PKCS7 padding
func SM4CBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	// First pad
	tmp := pkcs7Padding(src)

	// Then encrypt
	return sm4CBCEncrypt(key, tmp)
}

// SM4CBCPKCS7Encrypt combines CBC encryption and PKCS7 padding using as prng the passed to the function
func SM4CBCPKCS7EncryptWithRand(prng io.Reader, key, src []byte) ([]byte, error) {
	// First pad
	tmp := pkcs7Padding(src)

	// Then encrypt
	return sm4CBCEncryptWithRand(prng, key, tmp)
}

// SM4CBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding
func SM4CBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	// First decrypt
	pt, err := sm4CBCDecrypt(key, src)
	if err == nil {
		return pkcs7UnPadding(pt)
	}
	return nil, err
}

type sm4CBCPKCS7Encryptor struct{}

func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	return SM4CBCPKCS7Encrypt(key, plaintext)

}

type sm4CBCPKCS7Decryptor struct{}

func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	return SM4CBCPKCS7Decrypt(key, ciphertext)
}
