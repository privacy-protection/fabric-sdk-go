package ole

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/privacy-protection/cp-abe/core"
	"github.com/privacy-protection/cp-abe/parser"
	"github.com/privacy-protection/cp-abe/protos"
)

func Setup() (*protos.MasterKey, error) {
	return core.Init()
}

// fields: attributes of user
func KeyGen(masterKey *protos.MasterKey, fields []int) (*protos.Key, error) {
	attributes := make([]int32, len(fields))
	for i, field := range fields {
		attributes[i] = int32(field)
	}
	return core.Generate(masterKey, attributes)
}

// fields: policy tree
func Encrypt(data []byte, fields string, params *protos.Params) ([]byte, error) {
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

func Decrypt(key *protos.Key, ciphertext []byte) ([]byte, error) {
	c := &protos.Ciphertext{}
	err := proto.Unmarshal(ciphertext, c)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ciphertext error, %v", err)
	}
	return core.Decrypt(key, c)
}
