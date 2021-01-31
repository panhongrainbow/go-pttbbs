package types

func config() {
	TIME_LOCATION = setStringConfig("TIME_LOCATION", TIME_LOCATION)

	DEFAULT_PID_MAX = Pid_t(setIntConfig("DEFAULT_PID_MAX", int(DEFAULT_PID_MAX)))

	IS_ALLOW_CROSSDOMAIN = setBoolConfig("IS_ALLOW_CROSSDOMAIN", IS_ALLOW_CROSSDOMAIN)
}
