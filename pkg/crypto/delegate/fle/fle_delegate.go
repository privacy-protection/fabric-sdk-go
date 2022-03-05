package delegate

import (
	"fmt"

	kpabeProtos "github.com/privacy-protection/common/abe/protos/kpabe"
	kpabe "github.com/privacy-protection/kp-abe/delegate"
)

func KpabeFieldDelegate(oldKey *kpabeProtos.Key, field []int) (*kpabeProtos.Key, error) {
	newField := make([]int32, len(field))
	for i, num := range field {
		newField[i] = int32(num)
	}
	newKey, err := kpabe.FieldDelegate(oldKey, newField)
	if err != nil {
		return nil, fmt.Errorf("KpabeFieldDelegate error, %v", err)
	}
	return kpabe.ReRandomizing(newKey)
}
