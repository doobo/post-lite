package config

import "time"

type Config struct {
	Addr      string
	DataDir   string
	CertFile  string
	KeyFile   string
	PlainHTTP bool
	Timeout   time.Duration
	// ScriptTimeout bounds one pre-request script (JS sandbox). Short on
	// purpose: a script that does not finish is a bug, and the caller waiting on
	// the request has no way to cancel the script itself.
	ScriptTimeout time.Duration
	MaxHistory    int
	SecureCookie  bool
}
