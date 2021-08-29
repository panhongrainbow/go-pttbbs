package decode

import (
	"time"
)

// TimeFormat 為台北時間的時間格式
const TimeFormat = "2006-01-02 15:04:05"

// StampToCstStr 函式會把時間戳記轉成台北時間
func StampToCstStr(stamp int64) (string, error) {
	timeStamp := time.Unix(stamp, 0)
	return timeStamp.Format(TimeFormat), nil
}