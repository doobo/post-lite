package config

import "time"

type Config struct {
	Addr         string
	DataDir      string
	CertFile     string
	KeyFile      string
	PlainHTTP    bool
	Timeout      time.Duration
	MaxHistory   int
	SecureCookie bool
}
