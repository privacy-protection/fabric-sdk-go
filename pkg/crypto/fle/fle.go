package fle

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	cb "github.com/privacy-protection/common/abe/protos/common"
	kb "github.com/privacy-protection/common/abe/protos/kpabe"
	"github.com/privacy-protection/kp-abe/core"
)

// Setup 初始化函数
func Setup(bits int) (*kb.MasterKey, error) {
	return core.Init(bits)
}

// KeyGen 用户密钥生成函数
func KeyGen(masterKey *kb.MasterKey, fields []int) (*kb.Key, error) {
	n := len(fields)
	tree := &cb.Tree{
		Father:    make([]int32, n),
		Threshold: make([]int32, n+1),
		LeafId:    make([]int32, n),
		Leaf:      make([]*cb.Leaf, n),
	}
	tree.Threshold[0] = 1
	for i := 0; i < n; i++ {
		tree.LeafId[i] = int32(i + 1)
		tree.Leaf[i] = &cb.Leaf{AttributeId: int32(fields[i])}
	}
	return core.Generate(masterKey, tree)
}

// Encrypt 加密函数
func Encrypt(data []byte, fields []int, params *kb.Params) ([]byte, error) {
	attributes := make([]int32, len(fields))
	for i, field := range fields {
		attributes[i] = int32(field)
	}
	ciphertext, err := core.Encrypt(data, attributes, params)
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
func Decrypt(key *kb.Key, ciphertext []byte) ([]byte, error) {
	c := &kb.Ciphertext{}
	err := proto.Unmarshal(ciphertext, c)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ciphertext error, %v", err)
	}
	return core.Decrypt(key, c)
}
