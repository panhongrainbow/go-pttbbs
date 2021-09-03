package cache

import (
	"bytes"
	"fmt"
	"github.com/Ptt-official-app/go-pttbbs/decode"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/transform"
	"io"
	"io/ioutil"
	"os"
	"unsafe"

	"github.com/Ptt-official-app/go-pttbbs/cmsys"
	"github.com/Ptt-official-app/go-pttbbs/ptttype"
	"github.com/Ptt-official-app/go-pttbbs/types"

	log "github.com/sirupsen/logrus"
)

// LoadUHash
// Load user-hash into SHM.
func LoadUHash() (err error) {
	if Shm == nil {
		return ErrShmNotInit
	}

	// line: 58
	number := int32(0)
	Shm.ReadAt(
		unsafe.Offsetof(Shm.Raw.Number),
		unsafe.Sizeof(Shm.Raw.Number),
		unsafe.Pointer(&number),
	)

	loaded := int32(0)
	Shm.ReadAt(
		unsafe.Offsetof(Shm.Raw.Loaded),
		unsafe.Sizeof(Shm.Raw.Loaded),
		unsafe.Pointer(&loaded),
	)

	// XXX in case it's not assumed zero, this becomes a race...
	if number == 0 && loaded == 0 {
		// line: 60
		err = fillUHash(false)
		if err != nil {
			return err
		}

		// line: 61
		// use golang style.
		todayIsZeroBytes := [ptttype.TODAYISSZ]byte{}
		Shm.WriteAt(
			unsafe.Offsetof(Shm.Raw.TodayIs),
			unsafe.Sizeof(Shm.Raw.TodayIs),
			unsafe.Pointer(&todayIsZeroBytes),
		)

		// line: 62
		loaded = 1
		Shm.WriteAt(
			unsafe.Offsetof(Shm.Raw.Loaded),
			unsafe.Sizeof(Shm.Raw.Loaded),
			unsafe.Pointer(&loaded),
		)
	} else {
		// line: 65
		err = fillUHash(true)
		if err != nil {
			return err
		}
	}

	return nil
}

var uHashLoaderInvalidUserID = 0

// DecodeBig5 函式轉換 BIG5 to UTF-8
func DecodeBig5(s []byte) ([]byte, error) {
	I := bytes.NewReader(s)
	O := transform.NewReader(I, traditionalchinese.Big5.NewDecoder())
	d, e := ioutil.ReadAll(O)
	if e != nil {
		return nil, e
	}
	return d, nil
}

func fillUHash(isOnfly bool) error {
	log.Infof("fillUHash: start: isOnfly: %v", isOnfly)
	InitFillUHash(isOnfly)

	file, err := os.Open(ptttype.FN_PASSWD)
	if err != nil {
		log.Errorf("fillUHash: unable to open passwd: file: %v e: %v", ptttype.FN_PASSWD, err)
		return err
	}
	defer file.Close()

	uidInCache := ptttype.UIDInStore(0)

	uHashLoaderInvalidUserID = 0
	log.Infof("fillUHash: to for-loop: MAX_USERS: %v", ptttype.MAX_USERS)
	var count int
	for ; ; uidInCache++ {
		userecRaw, eachErr := ptttype.NewUserecRawWithFile(file)

		// 先由這裡開始控制測試
		if userecRaw != nil {
			count++

			if userecRaw.UserID == [13]uint8{83, 89, 83, 79, 80} { // SYSOP
				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 開始載入用戶

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 載入版本

				userecRaw.Version = 4194
				fmt.Printf("\u001B[35m 載入版本 %d\n", userecRaw.Version)

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 用戶編號

				var userID []uint8
				if userID, err = decode.ExtraToLetter(unsafe.Pointer(&userecRaw.UserID), 13); err != nil { // SYSOP
					return err
				}
				fmt.Printf("\u001B[35m 用戶編號 %s\n", string(userID))

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 用戶真名

				userecRaw.RealName = [20]uint8{67, 111, 100, 105, 100, 103, 77, 97, 110}
				var realname []uint8
				if realname, err = decode.ExtraToLetter(unsafe.Pointer(&userecRaw.RealName), 20); err != nil { // CodingMan
					return err
				}
				fmt.Printf("\u001B[35m 用戶真名 %s\n", string(realname))

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 用戶別名

				// 使用此網站解碼中文 https://dencode.com/en/string/bin?fbclid=IwAR35YkwOxg7_WG3lKBpfRWzYbtQkKscN6QWhSFCfdaAIj3oyix1VNKZs6HE
				userecRaw.Nickname = [24]uint8{175, 171}
				// 參考 https://pylist.com/topic/156.html 程式碼轉換成中文
				var nickname []uint8
				if nickname, err = decode.Big5toUtf8(unsafe.Pointer(&userecRaw.Nickname), 24); err != nil { // 神
					return err
				}
				fmt.Printf("\u001B[35m 用戶別名 %s\n", string(nickname))

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 用戶密碼

				userecRaw.PasswdHash = [14]uint8{98, 104, 119, 118, 79, 74, 116, 102, 84, 49, 84, 65, 73}
				var passwdHash []uint8
				if passwdHash, err = decode.ExtraToLetter(unsafe.Pointer(&userecRaw.PasswdHash), 14); err != nil { // bhwvOJtfT1TAI
					return err
				}
				fmt.Printf("\u001B[35m 用戶密碼 %s\n", string(passwdHash))

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 用戶標籤

				userecRaw.UFlag = ptttype.UF_BRDSORT|ptttype.UF_ADBANNER|ptttype.UF_DBCS_AWARE|ptttype.UF_DBCS_DROP_REPEAT|ptttype.UF_CURSOR_ASCII
				fmt.Printf("\u001B[35m 用戶標記 %x\n", userecRaw.UFlag) // 會顯示 2000a60
				// 2000a60 第一位為 0，就是沒有任何標籤的定義
				// 2000a60 第二位為 6，2 加 4 為 6，2 和 4 的值分別為 UF_BRDSORT 和 UF_ADBANNER
				// 2000a60 第三位為 a，2 加 8 為 10 (a)，2 和 8 的值分別為 UF_DBCS_AWARE 和 UF_DBCS_DROP_REPEAT
				// 2000a60 第七位為 2，2 的值為 UF_CURSOR_ASCII
				// 每一位置的數值都會有四個值，分別是 1 2 4 8，相加為 15，因是 16 進位，15 再加 1 就會進位了

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 用戶等級

				fmt.Printf("\u001B[35m 用戶等級 %o\n", userecRaw.UserLevel) // 會顯示 4000002007
				userecRaw.UserLevel = ptttype.PERM_BASIC|ptttype.PERM_CHAT|ptttype.PERM_PAGE|ptttype.PERM_BM|ptttype.PERM_SYSSUBOP
				// 4000002007 第一位為 7，1 加 2 加 4 為 7，1 2 4 的值分別為 ptttype.PERM_BASIC (基本權力) 和 ptttype.PERM_CHAT (進入聊天室) 和 ptttype.PERM_PAGE (找人聊天)
				// 4000002007 第四位為 2，2 為 ptttype.PERM_BM 板主
				// 4000002007 第十位為 4，4 為 PERM_SYSSUBOP 小組長
				// 每一位置的數值都會有三個值，分別是 1 2 4，相加為 7，因是 8 進位，7 再加 1 就會進位了

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 上網資歷

				userecRaw.NumLoginDays = 2
				fmt.Printf("\u001B[35m 上網資歷 %d\n", userecRaw.NumLoginDays)

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 第一次登入時間

				// 使用此網站把時間戳記轉換成人類可讀的時間 https://www.epochconverter.com/
				userecRaw.FirstLogin = 1600681288
				var firstLogin string // 時間戳記
				if firstLogin, err = decode.StampToCstStr(int64(userecRaw.FirstLogin)); err != nil { // 2020年9月21日星期一 17:41:28 GMT+08:00
					return err
				}
				fmt.Printf("\u001B[35m 第一次登入台北時間 %s\n", firstLogin)

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 最後一次登入時間

				userecRaw.LastLogin = 1600756094
				var lastLogin string // 時間戳記
				if lastLogin, err = decode.StampToCstStr(int64(userecRaw.LastLogin)); err != nil { // 2020年9月22日星期二 14:28:14 GMT+08:00
					return err
				}
				fmt.Printf("\u001B[35m 最後一次登入台北時間 %s\n", lastLogin)

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 用戶最後登入網路位置

				userecRaw.LastHost = [16]uint8{53, 57, 46, 49, 50, 52, 46, 49, 54, 55, 46, 50, 50, 54}
				var lastHost []uint8
				if lastHost, err = decode.ExtraToLetter(unsafe.Pointer(&userecRaw.LastHost), 16); err != nil { // 59.124.167.226
					return err
				}
				fmt.Printf("\u001B[35m 用戶最後登入網路位置 %s\n", string(lastHost))

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 用戶住家地址

				userecRaw.Address = [50]uint8{183, 115, 166, 203, 191, 164, 164, 108, 181, 234, 182, 109, 175, 81, 166, 179, 167, 248, 53, 52, 51, 184, 185}
				var address []uint8
				if address, err = decode.Big5toUtf8(unsafe.Pointer(&userecRaw.Address), 50); err != nil { // 新竹縣子虛鄉烏有村543號
					return err
				}
				fmt.Printf("\u001B[35m 用戶住家地址 %s\n", string(address))

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 用戶年紀是否超過十八歲

				userecRaw.Over18 = true
				fmt.Printf("\u001B[35m 用戶年紀是否超過十八歲 %v\n", userecRaw.Over18)

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 呼叫器狀態

				userecRaw.Pager = 1
				fmt.Printf("\u001B[35m 呼叫器狀態 %d\n", userecRaw.Pager)

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 用戶職業

				userecRaw.Career = [40]uint8{165, 254, 180, 186, 179, 110, 197, 233}
				var career []uint8
				if career, err = decode.Big5toUtf8(unsafe.Pointer(&userecRaw.Career), 40); err != nil { // 全景事業
					return err
				}
				fmt.Printf("\u001B[35m 用戶事業 %s\n", string(career))

				// >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> >>>>> 最後一次閱讀

				userecRaw.LastSeen = 1600756094
				var lastSeen string // 時間戳記
				if lastSeen, err = decode.StampToCstStr(int64(userecRaw.LastSeen)); err != nil { // 2020年9月22日星期二 14:28:14 GMT+08:00
					return err
				}
				fmt.Printf("\u001B[35m 最後一次閱讀 %s\n", lastSeen)
			}
			if userecRaw.UserID != [13]uint8{83, 89, 83, 79, 80} {
				// fmt.Println(userecRaw.UserID)
			}
		}

		if eachErr != nil {
			// io.EOF is reading correctly to the end the file.
			if eachErr == io.EOF {
				break
			}

			err = eachErr
			break
		}

		userecRawAddToUHash(uidInCache, userecRaw, isOnfly)
	}
	fmt.Println("共有資料筆數為", count, "只有 4 筆有效資料")

	if err != nil {
		log.Errorf("fillUHash: unable to read passwd: file: %v e: %v", ptttype.FN_PASSWD, err)
		return err
	}

	log.Infof("fillUHash: to write usernum: %v", uidInCache)

	Shm.WriteAt(
		unsafe.Offsetof(Shm.Raw.Number),
		unsafe.Sizeof(Shm.Raw.Number),
		unsafe.Pointer(&uidInCache),
	)

	return nil
}

func userecRawAddToUHash(uidInCache ptttype.UIDInStore, userecRaw *ptttype.UserecRaw, isOnfly bool) {
	// uhash use userid="" to denote free slot for new register
	// However, such entries will have the same hash key.
	// So we skip most of invalid userid to prevent lots of hash collision.
	if !userecRaw.UserID.IsValid() {
		// dirty hack, preserve few slot for new register
		uHashLoaderInvalidUserID++
		if uHashLoaderInvalidUserID > PRE_ALLOCATED_USERS {
			return
		}
	}

	h := cmsys.StringHashWithHashBits(userecRaw.UserID[:])

	shmUserID := ptttype.UserID_t{}
	Shm.ReadAt(
		unsafe.Offsetof(Shm.Raw.Userid)+ptttype.USER_ID_SZ*uintptr(uidInCache),
		ptttype.USER_ID_SZ,
		unsafe.Pointer(&shmUserID),
	)

	offsetNextInHash := unsafe.Offsetof(Shm.Raw.NextInHash)

	if !isOnfly || types.Cstrcmp(userecRaw.UserID[:], shmUserID[:]) != 0 {
		Shm.WriteAt(
			unsafe.Offsetof(Shm.Raw.Userid)+ptttype.USER_ID_SZ*uintptr(uidInCache),
			ptttype.USER_ID_SZ,
			unsafe.Pointer(&userecRaw.UserID),
		)

		Shm.WriteAt(
			unsafe.Offsetof(Shm.Raw.Money)+types.INT32_SZ*uintptr(uidInCache),
			types.INT32_SZ,
			unsafe.Pointer(&userecRaw.Money),
		)

		if ptttype.USE_COOLDOWN {
			zero := types.Time4(0)
			Shm.WriteAt(
				unsafe.Offsetof(Shm.Raw.CooldownTime)+types.TIME4_SZ*uintptr(uidInCache),
				types.TIME4_SZ,
				unsafe.Pointer(&zero),
			)
		}
	}

	p := h
	val := ptttype.UIDInStore(0)
	offsetHashHead := unsafe.Offsetof(Shm.Raw.HashHead)
	// offsetNextInHash := unsafe.Offsetof(Shm.Raw.NextInHash)
	isFirst := true

	Shm.ReadAt(
		offsetHashHead+types.INT32_SZ*uintptr(p),
		types.INT32_SZ,
		unsafe.Pointer(&val),
	)

	l := 0
	for val >= 0 && val < ptttype.MAX_USERS {
		if isOnfly && val == uidInCache { // already in hash
			return
		}

		l++
		// go to next
		// 1. setting p as val
		// 2. get val from next_in_hash[p]
		p = uint32(val)
		Shm.ReadAt(
			offsetNextInHash+types.INT32_SZ*uintptr(p),
			types.INT32_SZ,
			unsafe.Pointer(&val),
		)

		isFirst = false
	}

	// set next in hash as n
	offset := offsetHashHead
	if !isFirst {
		offset = offsetNextInHash
	}
	val = uidInCache
	Shm.WriteAt(
		offset+types.INT32_SZ*uintptr(p),
		types.INT32_SZ,
		unsafe.Pointer(&val),
	)

	// set next in hash as -1
	p = uint32(val)
	val = -1
	Shm.WriteAt(
		offsetNextInHash+types.INT32_SZ*uintptr(p),
		types.INT32_SZ,
		unsafe.Pointer(&val),
	)
}

func InitFillUHash(isOnfly bool) {
	if !isOnfly {
		toFillHashHead := [1 << ptttype.HASH_BITS]ptttype.UIDInStore{}
		for idx := range toFillHashHead {
			toFillHashHead[idx] = -1
		}
		Shm.WriteAt(
			unsafe.Offsetof(Shm.Raw.HashHead),
			unsafe.Sizeof(Shm.Raw.HashHead),
			unsafe.Pointer(&toFillHashHead),
		)
	} else {
		for idx := uint32(0); idx < (1 << ptttype.HASH_BITS); idx++ {
			checkHash(idx)
		}
	}
}

func checkHash(h uint32) {
	// p as delegate-pointer to the Shm.
	// in the beginning, p is the indicator of HashHead.
	// after 1st for-loop, p is in nextInHash.
	// val as the corresponding *p

	// line: 71
	p := h
	val := ptttype.UIDInStore(0)
	pval := &val
	valptr := unsafe.Pointer(pval)
	Shm.ReadAt(
		unsafe.Offsetof(Shm.Raw.HashHead)+types.INT32_SZ*uintptr(p),
		types.INT32_SZ,
		valptr,
	)

	// line: 72
	isFirst := true

	var offset uintptr
	offsetHashHead := unsafe.Offsetof(Shm.Raw.HashHead)
	offsetNextInHash := unsafe.Offsetof(Shm.Raw.NextInHash)

	userID := ptttype.UserID_t{}
	deep := 0
	for val != -1 {
		offset = offsetNextInHash
		if isFirst {
			offset = offsetHashHead
		}

		// check invalid pointer-val, set as -1  line: 74
		if val < -1 || val >= ptttype.MAX_USERS {
			log.Warnf("uhash_loader.checkHash: val invalid: h: %v p: %v val: %v isHead: %v", h, p, val, isFirst)
			*pval = -1
			Shm.WriteAt(
				offset+types.INT32_SZ*uintptr(p),
				types.INT32_SZ,
				valptr,
			)
			break
		}

		// get user-id: line: 75
		Shm.ReadAt(
			unsafe.Offsetof(Shm.Raw.Userid)+ptttype.USER_ID_SZ*uintptr(val),
			ptttype.USER_ID_SZ,
			unsafe.Pointer(&userID),
		)

		userIDHash := cmsys.StringHashWithHashBits(userID[:])

		// check hash as expected line: 76
		if userIDHash != h {
			// XXX
			// the result of the userID does not fit the h (broken?).
			// XXX uhash_loader is used only 1-time when starting the service.
			next := ptttype.UIDInStore(0)

			// get next from *p (val)
			Shm.ReadAt(
				offsetNextInHash+types.INT32_SZ*uintptr(val),
				types.INT32_SZ,
				unsafe.Pointer(&next),
			)
			log.Warnf("userID hash is not in the corresponding idx (to remove) (%v): userID: %v userIDHash: %v h: %v next: %v", deep, types.CstrToString(userID[:]), userIDHash, h, next)
			// remove current by setting current as the next, hopefully the next user can fit the userIDHash.
			*pval = next
			Shm.WriteAt(
				offset+types.INT32_SZ*uintptr(p),
				types.INT32_SZ,
				unsafe.Pointer(&next),
			)
		} else {
			// 1. p as val (pointer in NextInHash)
			// 2. update val as NextInHash[p]
			p = uint32(val)
			Shm.ReadAt(
				offsetNextInHash+types.INT32_SZ*uintptr(p),
				types.INT32_SZ,
				unsafe.Pointer(&val),
			)
			isFirst = false

		}

		// line: 87
		deep++
		if deep == PRE_ALLOCATED_USERS+10 { // need to be larger than the pre-allocated users.
			// warn if it's too deep, we may need to consider enlarge the hash-table.
			log.Warnf("checkHash deep: %v h: %v p: %v val: %v isFirst: %v", deep, h, p, val, isFirst)
		}
	}
}
