package config

import "os"

const defaultLogLevel = "info"

type Config struct {
	LogLevel string
}

func Load() Config {
	logLevel := os.Getenv("QS_LOG_LEVEL")

	if logLevel == "" {
		logLevel = defaultLogLevel
	}

	return Config{
		LogLevel: logLevel,
	}
}
