package main

import (
	"flag"
	"strings"

	"github.com/Ptt-official-app/go-pttbbs/api"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	jww "github.com/spf13/jwalterweatherman"
	"github.com/spf13/viper"
)

func initGin() (*gin.Engine, error) {
	router := gin.Default()

	router.POST("/", NewApi(api.Index, &api.IndexParams{}).Json)

	return router, nil
}

//initConfig
//
//Params
//	filename: ini filename
//
//Return
//	error: err
func initAllConfig(filename string) error {

	filenameList := strings.Split(filename, ".")
	if len(filenameList) == 1 {
		return ErrInvalidIni
	}

	filenamePrefix := strings.Join(filenameList[:len(filenameList)-1], ".")
	filenamePostfix := filenameList[len(filenameList)-1]
	viper.SetConfigName(filenamePrefix)
	viper.SetConfigType(filenamePostfix)
	viper.AddConfigPath("/etc/go-bbs")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		return err
	}

	log.Infof("viper keys: %v", viper.AllKeys())

	return InitConfig()
}

func initMain() error {
	jww.SetLogThreshold(jww.LevelDebug)
	jww.SetStdoutThreshold(jww.LevelDebug)
	log.SetLevel(log.InfoLevel)

	filename := ""
	flag.StringVar(&filename, "ini", "config.ini", "ini filename")
	flag.Parse()

	err := InitConfig()
	if err != nil {
		return err
	}
	err = api.InitConfig()
	if err != nil {
		return err
	}

	return initAllConfig(filename)
}

func main() {
	err := initMain()
	if err != nil {
		log.Errorf("unable to initMain: e: %v", err)
		return
	}
	router, err := initGin()
	if err != nil {
		return
	}

	_ = router.Run(HTTP_HOST)
}
