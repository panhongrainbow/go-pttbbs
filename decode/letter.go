package decode

import (
	"unsafe"
)

// ExtraToLetter 函式會把多餘的字串資料去除
func ExtraToLetter(ptr unsafe.Pointer, count int) ([]byte, error) {
	var nonZero []byte
	for i := 0; i < count; i++ {
		if (*[100]byte)(ptr)[i] == 0 {
			break
		}
		nonZero = append(nonZero, (*[100]byte)(ptr)[i])
	}

	return nonZero, nil
}