package fle

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/privacy-protection/kp-abe/core"
)

func Setup() (*core.MasterKey, error) {
	return core.Init()
}

func KeyGen(masterKey *core.MasterKey, fields []int) (*core.Key, error) {
	n := len(fields)
	tree := &core.Tree{
		Father:    make([]int32, n),
		Threshold: make([]int32, n+1),
		LeafId:    make([]int32, n),
		Leaf:      make([]*core.Leaf, n),
	}
	tree.Threshold[0] = 1
	for i := 0; i < n; i++ {
		tree.LeafId[i] = int32(i + 1)
		tree.Leaf[i] = &core.Leaf{AttributeId: int32(fields[i])}
	}
	return core.Generate(masterKey, tree)
}

func Encrypt(data []byte, field int, params *core.Params) ([]byte, error) {
	attributes := []int32{int32(field)}
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

func Decrypt(key *core.Key, ciphertext []byte) ([]byte, error) {
	c := &core.Ciphertext{}
	err := proto.Unmarshal(ciphertext, c)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ciphertext error, %v", err)
	}
	return core.Decrypt(key, c)
}
