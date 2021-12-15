package delegate

import (
	cpabeProtos "github.com/privacy-protection/common/abe/protos/cpabe"
	cpabe "github.com/privacy-protection/cp-abe/delegate"
)

func CpabeDelegate(oldKey *cpabeProtos.Key, newAttribute []int) (*cpabeProtos.Key, error) {
	attributes := make([]int32, len(newAttribute))
	for i, att := range newAttribute {
		attributes[i] = int32(att)
	}
	return cpabe.Delegate(oldKey, attributes)
}
