package ptt

import (
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/Ptt-official-app/go-pttbbs/cache"
	"github.com/Ptt-official-app/go-pttbbs/ptttype"
	"github.com/Ptt-official-app/go-pttbbs/testutil"
)

func Test_getNewUtmpEnt(t *testing.T) {
	type args struct {
		uinfo *ptttype.UserInfoRaw
	}
	tests := []struct {
		name           string
		args           args
		expectedUtmpID ptttype.UtmpID
		sleepTS        time.Duration
		wantErr        bool
	}{
		// TODO: Add test cases.
		{
			args:           args{testGetNewUtmpEnt0},
			expectedUtmpID: 5,
		},
		{
			args:           args{testGetNewUtmpEnt0},
			sleepTS:        time.Duration(1),
			expectedUtmpID: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			time.Sleep(tt.sleepTS * time.Second)
			gotUtmpID, err := getNewUtmpEnt(tt.args.uinfo)
			if (err != nil) != tt.wantErr {
				t.Errorf("getNewUtmpEnt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotUtmpID, tt.expectedUtmpID) {
				t.Errorf("getNewUtmpEnt() = %v, want %v", gotUtmpID, tt.expectedUtmpID)
			}

			got := &ptttype.UserInfoRaw{}
			cache.Shm.ReadAt(
				unsafe.Offsetof(cache.Shm.Raw.UInfo)+uintptr(gotUtmpID)*ptttype.USER_INFO_RAW_SZ,
				ptttype.USER_INFO_RAW_SZ,
				unsafe.Pointer(got),
			)

			testutil.TDeepEqual(t, "got", got, tt.args.uinfo)
		})
	}
}

func TestGetUser(t *testing.T) {
	setupTest()
	defer teardownTest()

	userID1 := &ptttype.UserID_t{}
	copy(userID1[:], []byte("SYSOP"))

	type args struct {
		userID *ptttype.UserID_t
	}
	tests := []struct {
		name         string
		args         args
		expectedUser *ptttype.UserecRaw
		wantErr      bool
	}{
		// TODO: Add test cases.
		{
			args: args{
				userID: userID1,
			},
			expectedUser: testUserecRaw1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUser, err := GetUser(tt.args.userID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotUser, tt.expectedUser) {
				t.Errorf("GetUser() = %v, want %v", gotUser, tt.expectedUser)
			}
		})
	}
}
