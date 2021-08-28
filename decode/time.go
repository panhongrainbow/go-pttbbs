package decode

import (
	"fmt"
	"time"
)

// StampToCst 函式會把時間戳記轉成台北時間
func StampToCst(stamp int64) (time.Time, error) {
	timeStamp := time.Unix(stamp, 0)
	fmt.Println(timeStamp)
	return timeStamp, nil
}