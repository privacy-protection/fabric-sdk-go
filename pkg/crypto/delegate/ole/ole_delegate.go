package delegate

import (
	cpabe "github.com/privacy-protection/cp-abe/core"
	cpabeProtos "github.com/privacy-protection/cp-abe/protos"
)

func CpabeDelegate(oldKey *cpabeProtos.Key, newAttribute []int) (*cpabeProtos.Key, error) {
	attributes := make([]int32, len(newAttribute))
	for i, att := range newAttribute {
		attributes[i] = int32(att)
	}
	return cpabe.Delegate(oldKey, attributes)
}
