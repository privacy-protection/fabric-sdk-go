package ole

import (
	"encoding/pem"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/privacy-protection/common/abe/parser"
	"github.com/privacy-protection/common/abe/protos/cpabe"
	"github.com/privacy-protection/common/abe/utils"
	"github.com/privacy-protection/cp-abe/core"
)

// Setup 初始化函数，生成主密钥
func Setup() (*cpabe.MasterKey, error) {
	return core.Init()
}

// KeyGen 用户密钥生成函数,输入用户的属性fields，生成用户密钥
func KeyGen(masterKey *cpabe.MasterKey, fields []string) (*cpabe.Key, error) {
	attributes := make([]int32, len(fields))
	for i, field := range fields {
		attributes[i] = int32(utils.Hash(field))
	}
	return core.Generate(masterKey, attributes)
}

// Encrypt 加密函数,输入访问树fields，明文数据data和公共参数，得到密文数据
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

// Decrypt 解密函数，输入用户密钥和密文，得到数据明文
func Decrypt(key *cpabe.Key, ciphertext []byte) ([]byte, error) {
	c := &cpabe.Ciphertext{}
	err := proto.Unmarshal(ciphertext, c)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ciphertext error, %v", err)
	}
	return core.Decrypt(key, c)
}

// 时间访问控制用，不可删
func EncryptWithTime(data []byte, fields string, params *cpabe.Params) ([]byte, error) {
	tree, _, err := parser.MyParsePolicy(fields, 32)
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

func EncryptAESKey(data []byte, policy string, params []byte) ([]byte, error) {
	tree, _, err := parser.MyParsePolicy(policy, 32)
	if err != nil {
		return nil, fmt.Errorf("parse error, %v", err)
	}
	block, _ := pem.Decode(params)
	cpparams := &cpabe.Params{}
	if err := proto.Unmarshal(block.Bytes, cpparams); err != nil {
		return nil, fmt.Errorf("unmarshal Params error, %v", err)
	}
	ciphertext, err := core.Encrypt(data, tree, cpparams)
	if err != nil {
		return nil, fmt.Errorf("encrypt error, %v", err)
	}
	bytes, err := proto.Marshal(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("marshal ciphertext error, %v", err)
	}
	return bytes, nil
}
