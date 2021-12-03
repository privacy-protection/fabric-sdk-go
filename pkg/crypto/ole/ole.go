package ole

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/privacy-protection/common/abe/parser"
	"github.com/privacy-protection/common/abe/protos/cpabe"
	"github.com/privacy-protection/cp-abe/core"
)

// Setup 初始化函数
func Setup() (*cpabe.MasterKey, error) {
	return core.Init()
}

// KeyGen 用户密钥生成函数,输入的fields是用户的属性
func KeyGen(masterKey *cpabe.MasterKey, fields []int) (*cpabe.Key, error) {
	attributes := make([]int32, len(fields))
	for i, field := range fields {
		attributes[i] = int32(field)
	}
	return core.Generate(masterKey, attributes)
}

// Encrypt 加密函数,输入的fields是访问树
func Encrypt(data []byte, fields string, params *cpabe.Params) ([]byte, error) {
	tree, err := parser.ParsePolicy(fields)
	if err != nil {
		return nil, fmt.Errorf("parse error, %v", err)
	}

	ciphertext, err := core.Encrypt(data, tree, params)
	if err != nil {
		return nil, fmt.Errorf("encrypt error, %v", err)
	}
	bytes, err := proto.Marshal(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("marshal ciphertext error, %v", err)
	}
	return bytes, nil
}

// Decrypt 解密函数
func Decrypt(key *cpabe.Key, ciphertext []byte) ([]byte, error) {
	c := &cpabe.Ciphertext{}
	err := proto.Unmarshal(ciphertext, c)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ciphertext error, %v", err)
	}
	return core.Decrypt(key, c)
}
