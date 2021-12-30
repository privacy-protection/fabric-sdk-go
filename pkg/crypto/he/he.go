//hybrid encryption
package he

import (
	"fmt"
	"log"

	sm2 "github.com/privacy-protection/hybrid-enc/sm2"
	sm4 "github.com/privacy-protection/hybrid-enc/sm4"
)

//sm4对称加密算法，输入对称密钥key和明文数据data，返回密文
func sm4Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	ciphertext, err := sm4.Encrypt(key, plaintext)
	if err != nil {
		log.Fatal(err)
	}
	return ciphertext, nil
}

//sm4对称解密算法，输入对称密钥key和密文数据ciphertext，返回明文
func sm4Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	plaintext, err := sm4.Decrypt(key, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	return plaintext, nil
}

//sm2 生成公私钥对，sm2.PrivateKey中包括了PublicKey
func sm2Generate() (sm2.PrivateKey, error) {
	privateKey, err := sm2.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	return *privateKey, nil
}

//sm2公钥加密 输入公钥publickey和明文数据data，返回密文
func sm2Encrypt(pubkey sm2.PublicKey, data []byte) ([]byte, error) {
	fmt.Println(data)
	ciphertext, err := sm2.Encrypt(&pubkey, data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ciphertext)
	return ciphertext, nil
}

//sm2公钥解密 输入私钥privatekey和密文数据ciphertext，返回明文
func sm2Decrypt(prikey sm2.PrivateKey, ciphertext []byte) ([]byte, error) {
	data, err := sm2.Decrypt(&prikey, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(data)
	return data, nil
}
