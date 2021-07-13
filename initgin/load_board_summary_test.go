package initgin

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Ptt-official-app/go-pttbbs/api"
)

func Test_LoadBoardSummary(t *testing.T) {
	setupTest()
	defer teardownTest()

	params := &api.LoadBoardSummaryParams{}

	type args struct {
		path     string
		username string
		passwd   string
		params   interface{}
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
		{
			args: args{
				path:     "/board/6_ALLPOST/summary",
				username: "SYSOP",
				passwd:   "123123",
				params:   params,
			},
		},
	}

	router, _ := InitGin()
	var wg sync.WaitGroup
	for _, tt := range tests {
		wg.Add(1)
		t.Run(tt.name, func(t *testing.T) {
			defer wg.Done()

			jwt := getJwt(router, tt.args.username, tt.args.passwd)
			w := httptest.NewRecorder()
			req := setRequest(tt.args.path, params, jwt, nil, "GET")
			router.ServeHTTP(w, req)

			body, _ := ioutil.ReadAll(w.Body)
			if w.Code != http.StatusOK {
				t.Errorf("code: %v body: %v", w.Code, string(body))
			}
		})
	}
	wg.Wait()
}
