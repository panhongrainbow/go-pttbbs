package decode

import (
	"bytes"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"unsafe"
)

// Big5toUtf8 函式把 BIG5 轉碼成 UTF8
func Big5toUtf8(ptr unsafe.Pointer, count int) ([]byte, error) {
	var nonZero []byte
	for i := 0; i < count; i++ {
		if (*[100]byte)(ptr)[i] == 0 {
			break
		}
		nonZero = append(nonZero, (*[100]byte)(ptr)[i])
	}

	I := bytes.NewReader(nonZero)
	O := transform.NewReader(I, traditionalchinese.Big5.NewDecoder())
	d, e := ioutil.ReadAll(O)
	if e != nil {
		return nil, e
	}
	return d, nil
}